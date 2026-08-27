// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

// The Unix side of the Go↔C socket bridge.
//
// This is the code that was inline in tailscale.go: socketpair(2) for both the
// stream and datagram bridges, and SCM_RIGHTS for handing an accepted
// connection's descriptor to the C consumer. Behaviour is unchanged — it moved
// behind a seam so a Windows implementation can exist, because Windows has
// neither socketpair() nor SCM_RIGHTS. See bridge_windows.go.

package main

import "C"

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// unixStream is the Go end of a stream socketpair.
type unixStream struct {
	f  *os.File
	fd int
}

func (s *unixStream) Read(p []byte) (int, error)  { return s.f.Read(p) }
func (s *unixStream) Write(p []byte) (int, error) { return s.f.Write(p) }
func (s *unixStream) Close() error                { return s.f.Close() }

func (s *unixStream) CloseRead() error  { return syscall.Shutdown(s.fd, syscall.SHUT_RD) }
func (s *unixStream) CloseWrite() error { return syscall.Shutdown(s.fd, syscall.SHUT_WR) }

// sendConn hands an accepted connection to the C consumer as an SCM_RIGHTS
// descriptor, with the remote address carried inband in a fixed-size field so
// the framing stays aligned per accepted fd.
//
// The receiver gets a *fresh* fd number — a dup of the same open file
// description — which is why TsnetAccept keys its remote-address table by the
// fd it receives rather than by connFd. (Patch 021.)
func (s *unixStream) sendConn(connFd C.int, addrBuf []byte) error {
	rights := syscall.UnixRights(int(connFd))
	return syscall.Sendmsg(s.fd, addrBuf, rights, nil, 0)
}

// newBridgeStreamPair returns the Go end and the C-side descriptor of a
// connected stream pair.
func newBridgeStreamPair() (bridgeStream, C.int, error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, 0, err
	}
	return &unixStream{f: os.NewFile(uintptr(fds[1]), "socketpair-r"), fd: fds[1]}, C.int(fds[0]), nil
}

// recvBridgeConn is the consumer half of sendConn, called on the C-side
// descriptor the C caller passes to tailscale_accept.
func recvBridgeConn(listenerFd C.int, addrBuf []byte) (connFd C.int, n int, err error) {
	oob := make([]byte, unix.CmsgLen(int(unsafe.Sizeof((C.int)(0)))))
	n, oobn, _, _, err := syscall.Recvmsg(int(listenerFd), addrBuf, oob, 0)
	if err != nil {
		return 0, 0, err
	}
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, 0, err
	}
	if len(scms) != 1 {
		return 0, 0, fmt.Errorf("libtailscale: got %d control messages, want 1", len(scms))
	}
	fds, err := syscall.ParseUnixRights(&scms[0])
	if err != nil {
		return 0, 0, err
	}
	if len(fds) != 1 {
		return 0, 0, fmt.Errorf("libtailscale: got %d FDs, want 1", len(fds))
	}
	return C.int(fds[0]), n, nil
}

// unixPacket is the Go end of a datagram socketpair.
type unixPacket struct{ fd int }

func (p *unixPacket) Read(b []byte) (int, error)  { return syscall.Read(p.fd, b) }
func (p *unixPacket) Write(b []byte) (int, error) { return syscall.Write(p.fd, b) }
func (p *unixPacket) Close() error                { return syscall.Close(p.fd) }

// newBridgePacketPair returns the Go end and the C-side descriptor of a
// connected datagram pair, with both ends' socket buffers raised to sockBuf.
//
// macOS defaults SOCK_DGRAM unix socket buffers to a few KB. RTP at 60fps with
// the occasional keyframe burst overflows that and the kernel drops datagrams
// silently.
func newBridgePacketPair(sockBuf int) (bridgePacket, C.int, error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, 0, err
	}
	for _, fd := range fds {
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sockBuf)
		syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, sockBuf)
	}
	return &unixPacket{fd: fds[1]}, C.int(fds[0]), nil
}

// closeBridgeCSide closes a descriptor this process handed to C. Used on the
// teardown path where Go owns the fd end to end.
func closeBridgeCSide(fd C.int) error { return syscall.Close(int(fd)) }
