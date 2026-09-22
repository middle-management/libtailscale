// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

// The Windows side of the Go↔C socket bridge.
//
// Windows has neither of the primitives the Unix implementation is built on:
//
//   - No socketpair(). Win10 1803+ has AF_UNIX *stream* sockets, but no
//     socketpair() and no AF_UNIX datagram mode at all — and the datagram
//     bridge below carries UDP, where message boundaries are load-bearing.
//     So both flavours are emulated on the loopback interface.
//
//   - No SCM_RIGHTS. There is no way to attach a handle to a datagram. But
//     none is needed: the Go and C sides live in the same process and
//     therefore share one handle table, so the accepted connection's handle
//     *value* can simply be written down the control channel. The Unix
//     machinery exists for a cross-process constraint that does not apply.
//
// A trap to be aware of when extending this: several Winsock wrappers in Go's
// syscall package compile on Windows but are EWINDOWS stubs that always fail at
// runtime — Accept, Recvfrom, Sendto, SetsockoptTimeval. Socket, Bind, Listen,
// Connect, Getsockname, Closesocket, WSARecv and WSASend are real. That is why
// the accept below goes through Go's net package rather than syscall.Accept.
//
// The primitives here are the ones proven on a Windows runner by
// spikes/windows-tsnet-bridge before this was written.

package main

import "C"

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// handleToCInt narrows a SOCKET to the `int` the C API types a connection as
// (tailscale_conn). A Windows SOCKET is UINT_PTR — 64 bits on amd64 — but
// handle values are 32-bit-significant, which the spike asserts rather than
// assumes.
func handleToCInt(h syscall.Handle) (C.int, error) {
	if syscall.Handle(int32(h)) != h {
		return 0, fmt.Errorf("libtailscale: socket handle %#x does not fit in a C int", uintptr(h))
	}
	return C.int(int32(h)), nil
}

// winStream is the Go end of an emulated stream socketpair. *net.TCPConn
// already provides Read/Write/Close/CloseRead/CloseWrite, so the Go side is
// poller-managed for free — better than the Unix end, which pumps a raw fd on a
// dedicated OS thread.
type winStream struct{ c *net.TCPConn }

func (s *winStream) Read(p []byte) (int, error)  { return s.c.Read(p) }
func (s *winStream) Write(p []byte) (int, error) { return s.c.Write(p) }
func (s *winStream) Close() error                { return s.c.Close() }
func (s *winStream) CloseRead() error            { return s.c.CloseRead() }
func (s *winStream) CloseWrite() error           { return s.c.CloseWrite() }

// connHandoffAddrLen matches the fixed address field the Unix side sends
// alongside SCM_RIGHTS, so both platforms frame the handoff identically.
const connHandoffAddrLen = 256

// sendConn announces an accepted connection to the C consumer: the handle
// value followed by the same fixed-size address field the Unix path uses.
//
// One write, so the stream carries whole records and the reader can consume a
// fixed 4+256 bytes per accepted connection.
func (s *winStream) sendConn(connFd C.int, addrBuf []byte) error {
	msg := make([]byte, 4+connHandoffAddrLen)
	binary.LittleEndian.PutUint32(msg[:4], uint32(int32(connFd)))
	copy(msg[4:], addrBuf)
	_, err := s.c.Write(msg)
	return err
}

// newBridgeStreamPair emulates socketpair(AF_LOCAL, SOCK_STREAM) with the
// standard loopback dance: listen, connect, accept, drop the listener.
func newBridgeStreamPair() (bridgeStream, C.int, error) {
	// tcp4 explicitly: on a dual-stack host "tcp" can bind ::1, which the raw
	// AF_INET socket below could then never reach.
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	defer l.Close()

	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("libtailscale: listener address is %T, want *net.TCPAddr", l.Addr())
	}

	cSide, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, 0, err
	}

	type accepted struct {
		conn net.Conn
		err  error
	}
	acceptCh := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		acceptCh <- accepted{c, err}
	}()

	sa := &syscall.SockaddrInet4{Port: addr.Port}
	copy(sa.Addr[:], addr.IP.To4())
	if err := syscall.Connect(cSide, sa); err != nil {
		syscall.Closesocket(cSide)
		return nil, 0, err
	}

	got := <-acceptCh
	if got.err != nil {
		syscall.Closesocket(cSide)
		return nil, 0, got.err
	}

	tcp, ok := got.conn.(*net.TCPConn)
	if !ok {
		got.conn.Close()
		syscall.Closesocket(cSide)
		return nil, 0, fmt.Errorf("libtailscale: accepted %T, want *net.TCPConn", got.conn)
	}

	fdC, err := handleToCInt(cSide)
	if err != nil {
		tcp.Close()
		syscall.Closesocket(cSide)
		return nil, 0, err
	}
	return &winStream{c: tcp}, fdC, nil
}

// recvBridgeConn is the consumer half of sendConn, reading the fixed 4+256-byte
// record off the C-side handle the caller passed to tailscale_accept.
func recvBridgeConn(listenerFd C.int, addrBuf []byte) (connFd C.int, n int, err error) {
	msg := make([]byte, 4+connHandoffAddrLen)
	read := 0
	for read < len(msg) {
		got, err := recvHandle(syscall.Handle(listenerFd), msg[read:])
		if err != nil {
			return 0, 0, err
		}
		if got == 0 {
			return 0, 0, fmt.Errorf("libtailscale: listener control channel closed")
		}
		read += got
	}
	connFd = C.int(int32(binary.LittleEndian.Uint32(msg[:4])))
	n = copy(addrBuf, msg[4:])
	return connFd, n, nil
}

// winPacket is the Go end of an emulated datagram socketpair. A connected
// *net.UDPConn preserves message boundaries, which is what the framed UDP
// bridge depends on.
type winPacket struct{ c *net.UDPConn }

func (p *winPacket) Read(b []byte) (int, error)  { return p.c.Read(b) }
func (p *winPacket) Write(b []byte) (int, error) { return p.c.Write(b) }
func (p *winPacket) Close() error                { return p.c.Close() }

// newBridgePacketPair emulates socketpair(AF_LOCAL, SOCK_DGRAM) with two
// loopback UDP sockets, each connected to the other so both ends can use
// unqualified read/write and the kernel drops anything from elsewhere.
func newBridgePacketPair(sockBuf int) (bridgePacket, C.int, error) {
	cSide, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, 0, err
	}
	if err := syscall.Bind(cSide, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		syscall.Closesocket(cSide)
		return nil, 0, err
	}
	csa, err := syscall.Getsockname(cSide)
	if err != nil {
		syscall.Closesocket(cSide)
		return nil, 0, err
	}
	c4, ok := csa.(*syscall.SockaddrInet4)
	if !ok {
		syscall.Closesocket(cSide)
		return nil, 0, fmt.Errorf("libtailscale: C-side address is %T, want *syscall.SockaddrInet4", csa)
	}

	// Connect the Go end to the C end and vice versa, so both are point-to-point.
	goConn, err := net.DialUDP("udp4",
		&net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 0},
		&net.UDPAddr{IP: net.IP(c4.Addr[:]).To4(), Port: c4.Port})
	if err != nil {
		syscall.Closesocket(cSide)
		return nil, 0, err
	}
	goAddr, ok := goConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		goConn.Close()
		syscall.Closesocket(cSide)
		return nil, 0, fmt.Errorf("libtailscale: Go-side address is %T, want *net.UDPAddr", goConn.LocalAddr())
	}
	peer := &syscall.SockaddrInet4{Port: goAddr.Port}
	copy(peer.Addr[:], goAddr.IP.To4())
	if err := syscall.Connect(cSide, peer); err != nil {
		goConn.Close()
		syscall.Closesocket(cSide)
		return nil, 0, err
	}

	// Same reasoning as the Unix path: default datagram buffers are far too
	// small for RTP at 60fps with keyframe bursts, and overflow drops silently.
	syscall.SetsockoptInt(cSide, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockBuf)
	syscall.SetsockoptInt(cSide, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockBuf)
	if rc, err := goConn.SyscallConn(); err == nil {
		rc.Control(func(fd uintptr) {
			h := syscall.Handle(fd)
			syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockBuf)
			syscall.SetsockoptInt(h, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockBuf)
		})
	}

	fdC, err := handleToCInt(cSide)
	if err != nil {
		goConn.Close()
		syscall.Closesocket(cSide)
		return nil, 0, err
	}
	return &winPacket{c: goConn}, fdC, nil
}

// recvHandle reads from a raw handle the way C's recv() would. syscall.Recv
// does not exist on Windows and syscall.Recvfrom is an EWINDOWS stub, so this
// goes through WSARecv, which is real.
func recvHandle(h syscall.Handle, p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	buf := syscall.WSABuf{Len: uint32(len(p)), Buf: &p[0]}
	var n, flags uint32
	if err := syscall.WSARecv(h, &buf, 1, &n, &flags, nil, nil); err != nil {
		return 0, err
	}
	return int(n), nil
}

// closeBridgeCSide closes a handle this process handed to C.
func closeBridgeCSide(fd C.int) error { return syscall.Closesocket(syscall.Handle(fd)) }
