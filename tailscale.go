// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// A Go c-archive of the tsnet package. See tailscale.h for details.
package main

//#include "errno.h"
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func main() {}

// servers tracks all the allocated *tsnet.Server objects.
var servers struct {
	mu   sync.Mutex
	next C.int
	m    map[C.int]*server
}

type server struct {
	s       *tsnet.Server
	lastErr string
	started bool
}

func getServer(sd C.int) *server {
	servers.mu.Lock()
	defer servers.mu.Unlock()
	return servers.m[sd]
}

// listeners tracks all the tsnet_listener objects allocated via tsnet_listen.
var listeners struct {
	mu sync.Mutex
	m  map[C.int]*listener
}

type listener struct {
	s  *server
	ln net.Listener
	sp bridgeStream // go side of the bridge pair whose C end went to C
	mu sync.Mutex
	m  map[C.int]net.Addr //maps fds to remote addresses for lookup
}

// conns tracks all the pipe(2)s allocated via tsnet_dial.
var conns struct {
	mu sync.Mutex
	m  map[C.int]*conn // keyed by the FD given to C (w)
}

type conn struct {
	s *tsnet.Server
	c net.Conn
	r bridgeStream // r is the local socket to the C client
}

func (s *server) recErr(err error) C.int {
	if err == nil {
		s.lastErr = ""
		return 0
	}
	s.lastErr = err.Error()
	return -1
}

//export TsnetNewServer
func TsnetNewServer() C.int {
	servers.mu.Lock()
	defer servers.mu.Unlock()

	if servers.m == nil {
		servers.m = map[C.int]*server{}
		hostinfo.SetApp("libtailscale")
	}
	if servers.next == 0 {
		servers.next = 42<<16 + 1
	}
	sd := servers.next
	servers.next++
	s := &server{s: &tsnet.Server{}}
	servers.m[sd] = s
	return (C.int)(sd)
}

//export TsnetStart
func TsnetStart(sd C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	err := s.s.Start()
	if err == nil {
		s.started = true
	}
	return s.recErr(err)
}

//export TsnetUp
func TsnetUp(sd C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	_, err := s.s.Up(context.Background()) // cancellation is via TsnetClose
	if err == nil {
		s.started = true
	}
	return s.recErr(err)
}

//export TsnetClose
func TsnetClose(sd C.int) C.int {
	servers.mu.Lock()
	s := servers.m[sd]
	if s != nil {
		delete(servers.m, sd)
	}
	servers.mu.Unlock()

	if s == nil {
		return C.EBADF
	}

	// TODO: cancel Up
	// TODO: close related listeners / conns.
	if !s.started {
		// Server was never started, nothing to close.
		return 0
	}
	if err := s.s.Close(); err != nil {
		s.s.Logf("tailscale_close: failed with %v", err)
		return -1
	}

	return 0
}

//export TsnetGetIps
func TsnetGetIps(sd C.int, buf *C.char, buflen C.size_t) C.int {
	if buf == nil {
		panic("errmsg passed nil buf")
	} else if buflen == 0 {
		panic("errmsg passed buflen of 0")
	}

	servers.mu.Lock()
	s := servers.m[sd]
	servers.mu.Unlock()

	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)

	if s == nil {
		out[0] = '\x00'
		return C.EBADF
	}

	ip4, ip6 := s.s.TailscaleIPs()
	joined := strings.Join([]string{ip4.String(), ip6.String()}, ",")
	n := copy(out, joined)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

//export TsnetErrmsg
func TsnetErrmsg(sd C.int, buf *C.char, buflen C.size_t) C.int {
	if buf == nil {
		panic("errmsg passed nil buf")
	} else if buflen == 0 {
		panic("errmsg passed buflen of 0")
	}

	servers.mu.Lock()
	s := servers.m[sd]
	servers.mu.Unlock()

	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)
	if s == nil {
		out[0] = '\x00'
		return C.EBADF
	}
	n := copy(out, s.lastErr)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

//export TsnetListen
func TsnetListen(sd C.int, network, addr *C.char, listenerOut *C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	ln, err := s.s.Listen(C.GoString(network), C.GoString(addr))
	if err != nil {
		return s.recErr(err)
	}
	s.started = true
	return bridgeListen(s, ln, listenerOut)
}

// bridgeListen wires an already-open net.Listener to a C-consumable
// listener fd: the accept pump, the SCM_RIGHTS (or Windows record)
// handoff, and the teardown-on-close plumbing. Factored out of
// TsnetListen so the guest (control-plane-free) surface can serve its
// callback-delivered connections through the exact same machinery —
// including tailscale_accept and tailscale_getremoteaddr on the C side.
// s is only used for error recording and logging; its tsnet server may
// be nil (the guest surface passes a bare error-sink server).
func bridgeListen(s *server, ln net.Listener, listenerOut *C.int) C.int {
	// The tailscale_listener we return to C is one side of a bridge socket
	// pair (socketpair(2) on Unix, a loopback pair on Windows).
	// We do this so we can proactively call ln.Accept in a goroutine and
	// feed an fd for the connection through the listener. This lets C use
	// epoll on the tailscale_listener to know if it should call
	// tailscale_accept, which avoids a blocking call on the far side.
	spRaw, fdC, err := newBridgeStreamPair()
	if err != nil {
		return s.recErr(err)
	}
	// The accept handoff needs more than the io half of the seam: on Unix it
	// is an SCM_RIGHTS sendmsg, on Windows a plain record write.
	sp, ok := spRaw.(bridgeConnSender)
	if !ok {
		spRaw.Close()
		return s.recErr(fmt.Errorf("libtailscale: bridge stream %T cannot hand over connections", spRaw))
	}

	listeners.mu.Lock()
	if listeners.m == nil {
		listeners.m = map[C.int]*listener{}
	}
	listener := &listener{s: s, ln: ln, sp: sp, m: map[C.int]net.Addr{}}
	listeners.m[fdC] = listener
	listeners.mu.Unlock()

	cleanup := func() {
		// If fdC is closed on the C side, then we end up calling
		// into cleanup twice. Be careful to avoid closing the Go end
		// twice as the descriptor may have been reallocated.
		listeners.mu.Lock()
		if tsLn, ok := listeners.m[fdC]; ok && tsLn.ln == ln {
			delete(listeners.m, fdC)
			sp.Close()
		}
		listeners.mu.Unlock()

		ln.Close()
	}
	go func() {
		// fdC is never written to, so trying to read from sp blocks
		// until fdC is closed. We use this as a signal that C is
		// done with the listener, and we can tear it down.
		var buf [256]byte
		sp.Read(buf[:])
		cleanup()
	}()
	go func() {
		defer cleanup()
		for {
			netConn, err := ln.Accept()
			if err != nil {
				return
			}
			var connFd C.int
			if err := newConn(s, netConn, &connFd); err != nil {
				if s.s != nil && s.s.Logf != nil {
					s.s.Logf("libtailscale.accept: newConn: %v", err)
				}
				netConn.Close()
				continue
			}
			// Carry the remote address inband alongside the handed-over
			// descriptor so the consumer (TsnetAccept) can key it by the
			// number it actually receives. Keying the lookup table by connFd
			// here is wrong on Unix: SCM_RIGHTS hands the receiver a *fresh*
			// fd number (a dup of the same open file description), so a later
			// tailscale_getremoteaddr(receivedFd) misses the connFd-keyed
			// entry and returns EBADF non-deterministically. A fixed-size
			// field keeps the framing aligned per accepted connection.
			var addrBuf [256]byte
			copy(addrBuf[:255], netConn.RemoteAddr().String())
			if err := sp.sendConn(connFd, addrBuf[:]); err != nil {
				// We handle sp being closed in the read goroutine above.
				if s.s != nil && s.s.Logf != nil {
					s.s.Logf("libtailscale.accept: sendConn failed: %v", err)
				}
				netConn.Close()
				// fallthrough to close connFd, then continue Accept()ing
			}

			closeBridgeCSide(connFd) // now owned by the receiver
		}
	}()

	*listenerOut = fdC
	return 0
}

//export TsnetAccept
func TsnetAccept(listenerFd C.int, connOut *C.int) C.int {
	listeners.mu.Lock()
	ln := listeners.m[listenerFd]
	listeners.mu.Unlock()

	if ln == nil {
		return C.EBADF
	}

	// The accept goroutine sends the connection's remote address inband as a
	// fixed 256-byte field alongside the descriptor (see the sender side).
	addrBuf := make([]byte, 256)
	connFd, n, err := recvBridgeConn(listenerFd, addrBuf)
	if err != nil {
		return ln.s.recErr(err)
	}
	*connOut = connFd

	// Key the remote-address table by the fd we just handed C — the same fd
	// it will pass back to tailscale_getremoteaddr. (See the sender side in
	// the accept goroutine for why connFd can't be used as the key.)
	if n > 0 {
		if i := bytes.IndexByte(addrBuf[:n], 0); i >= 0 {
			n = i
		}
		ln.mu.Lock()
		ln.m[*connOut] = stringAddr(addrBuf[:n])
		ln.mu.Unlock()
	}

	return 0
}

// stringAddr is a net.Addr that carries only a pre-resolved address string.
// It shuttles a connection's remote address from the accept goroutine to the
// consumer (TsnetAccept) without depending on fd-number identity across the
// SCM_RIGHTS handoff.
type stringAddr string

func (a stringAddr) Network() string { return "tcp" }
func (a stringAddr) String() string  { return string(a) }

func newConn(s *server, netConn net.Conn, connOut *C.int) error {
	r, fdC, err := newBridgeStreamPair()
	if err != nil {
		return err
	}
	c := &conn{s: s.s, c: netConn, r: r}

	conns.mu.Lock()
	if conns.m == nil {
		conns.m = make(map[C.int]*conn)
	}
	conns.m[fdC] = c
	conns.mu.Unlock()

	connCleanup := func() {
		var inCleanup bool
		conns.mu.Lock()
		if tsConn, ok := conns.m[fdC]; ok && tsConn.c == netConn {
			delete(conns.m, fdC)
			inCleanup = true
		}
		conns.mu.Unlock()

		if !inCleanup {
			return
		}

		r.Close()
		netConn.Close()
	}
	go func() {
		defer connCleanup()
		var b [1 << 16]byte
		io.CopyBuffer(r, netConn, b[:])
		r.CloseWrite()
		if cr, ok := netConn.(interface{ CloseRead() error }); ok {
			cr.CloseRead()
		}
	}()
	go func() {
		defer connCleanup()
		var b [1 << 16]byte
		io.CopyBuffer(netConn, r, b[:])
		r.CloseRead()
		if cw, ok := netConn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()

	*connOut = fdC
	return nil
}

//export TsnetGetRemoteAddr
func TsnetGetRemoteAddr(listener C.int, conn C.int, buf *C.char, buflen C.size_t) C.int {
	if buf == nil {
		panic("errmsg passed nil buf")
	} else if buflen == 0 {
		panic("errmsg passed buflen of 0")
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)

	listeners.mu.Lock()
	defer listeners.mu.Unlock()
	l := listeners.m[listener]
	if l == nil {
		out[0] = '\x00'
		return C.EBADF
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	addr, ok := l.m[conn]
	if !ok {
		out[0] = '\x00'
		return C.EBADF
	}

	ip := extractIP(addr.String())

	n := copy(out, ip)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'
	return 0
}

// Strips the port from connection IPs
func extractIP(ipWithPort string) string {
	re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|\[([0-9a-fA-F:]+)\]`)
	match := re.FindString(ipWithPort)
	return match
}

//export TsnetDial
func TsnetDial(sd C.int, network, addr *C.char, connOut *C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	netConn, err := s.s.Dial(context.Background(), C.GoString(network), C.GoString(addr))
	if err != nil {
		return s.recErr(err)
	}
	s.started = true
	if err := newConn(s, netConn, connOut); err != nil {
		return s.recErr(err)
	}
	return 0
}

//export TsnetSetDir
func TsnetSetDir(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.Dir = C.GoString(str)
	return 0
}

//export TsnetSetHostname
func TsnetSetHostname(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.Hostname = C.GoString(str)
	return 0
}

//export TsnetSetAuthKey
func TsnetSetAuthKey(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.AuthKey = C.GoString(str)
	return 0
}

//export TsnetSetControlURL
func TsnetSetControlURL(sd C.int, str *C.char) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	s.s.ControlURL = C.GoString(str)
	return 0
}

//export TsnetSetEphemeral
func TsnetSetEphemeral(sd C.int, e int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	if e == 0 {
		s.s.Ephemeral = false
	} else {
		s.s.Ephemeral = true
	}
	return 0
}

//export TsnetSetLogFD
func TsnetSetLogFD(sd, fd C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	if fd == -1 {
		s.s.Logf = logger.Discard
		return 0
	}
	f := os.NewFile(uintptr(fd), "logfd")
	s.s.Logf = func(format string, args ...any) {
		fmt.Fprintf(f, format, args...)
		fmt.Fprintf(f, "\n")
	}
	return 0
}

//export TsnetLoopback
func TsnetLoopback(sd C.int, addrOut *C.char, addrLen C.size_t, proxyOut *C.char, localOut *C.char) C.int {
	// Panic here to ensure we always leave the out values NUL-terminated.
	if addrOut == nil {
		panic("loopback_api passed nil addr_out")
	} else if addrLen == 0 {
		panic("loopback_api passed addrlen of 0")
	} else if proxyOut == nil {
		panic("loopback_api passed nil proxy_cred_out")
	} else if localOut == nil {
		panic("loopback_api passed nil local_api_cred_out")
	}

	// Start out NUL-termianted to cover error conditions.
	*addrOut = '\x00'
	*localOut = '\x00'
	*proxyOut = '\x00'

	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	addr, proxyCred, localAPICred, err := s.s.Loopback()
	if err != nil {
		return s.recErr(err)
	}
	if len(proxyCred) != 32 {
		return s.recErr(fmt.Errorf("libtailscale: len(proxyCred)=%d, want 32", len(proxyCred)))
	}
	if len(localAPICred) != 32 {
		return s.recErr(fmt.Errorf("libtailscale: len(localAPICred)=%d, want 32", len(localAPICred)))
	}

	out := unsafe.Slice((*byte)(unsafe.Pointer(addrOut)), addrLen)
	n := copy(out, addr)
	if n >= len(out) {
		out[len(out)-1] = '\x00' // always NUL-terminate
		return C.ERANGE
	}
	out[n] = '\x00'

	// proxyOut and localOut are non-nil and 33 bytes long because
	// they are defined in C as char cred_out[static 33].
	out = unsafe.Slice((*byte)(unsafe.Pointer(proxyOut)), 33)
	copy(out, proxyCred)
	out[32] = '\x00'
	out = unsafe.Slice((*byte)(unsafe.Pointer(localOut)), 33)
	copy(out, localAPICred)
	out[32] = '\x00'

	return 0
}

//export TsnetStatusJSON
func TsnetStatusJSON(sd C.int, jsonOut **C.char) C.int {
	if jsonOut == nil {
		panic("status_json passed nil json_out")
	}
	*jsonOut = nil
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}
	// LocalClient rides tsnet's in-memory LocalAPI listener — unlike
	// Loopback()'s TCP listener it cannot be reclaimed by the OS while
	// the process is suspended (iOS), so status reads keep working on
	// long-lived nodes.
	lc, err := s.s.LocalClient()
	if err != nil {
		return s.recErr(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := lc.Status(ctx)
	if err != nil {
		return s.recErr(err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return s.recErr(err)
	}
	*jsonOut = C.CString(string(b))
	return 0
}

//export TsnetEnableFunnelToLocalhostPlaintextHttp1
func TsnetEnableFunnelToLocalhostPlaintextHttp1(sd C.int, localhostPort C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	ctx := context.Background()
	lc, err := s.s.LocalClient()
	if err != nil {
		return s.recErr(err)
	}

	st, err := lc.StatusWithoutPeers(ctx)
	if err != nil {
		return s.recErr(err)
	}
	domain := st.CertDomains[0]

	hp := ipn.HostPort(net.JoinHostPort(domain, strconv.Itoa(443)))
	tcpForward := fmt.Sprintf("127.0.0.1:%d", localhostPort)
	sc := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{
			443: {
				TCPForward:   tcpForward,
				TerminateTLS: domain,
			},
		},
		AllowFunnel: map[ipn.HostPort]bool{
			hp: true,
		},
	}

	lc.SetServeConfig(ctx, sc)
	if !sc.AllowFunnel[hp] {
		return s.recErr(fmt.Errorf("libtailscale: failed to enable funnel"))
	}

	return 0
}

// packetListeners tracks tsnet UDP PacketConns surfaced to C as
// datagram bridge descriptors. tsnet.Server.Listen does not support UDP
// (Go's net.Listen has no UDP variant), so libtailscale upstream
// only exposes TCP listeners. This adds a parallel UDP path via
// tsnet.Server.ListenPacket. Each datagram on the socketpair is framed
// as [1B addr_len][addr_bytes][payload] so the C side can preserve the
// per-packet source/destination address — a real UDP socket gets that
// from recvfrom/sendto, which the bridge can't pass through natively.
var packetListeners struct {
	mu sync.Mutex
	m  map[C.int]*packetListener
}

type packetListener struct {
	s    *server
	pc   net.PacketConn
	pkt  bridgePacket // go side of the datagram bridge pair
	cFd  C.int        // C side fd (key in packetListeners.m)
	once sync.Once
}

// closeOnce releases the listener exactly once regardless of which caller
// arrives first — the external TsnetListenPacketClose or a bridge goroutine
// exiting on its own (e.g. due to a write error). sync.Once guarantees the
// body runs at most once even under concurrent calls.
//
// Ordering inside the body matters:
//  1. Remove from the map first (under lock) so no new caller can see this pl.
//  2. Close the Go side of the bridge pair — unblocks the read in the
//     bridge→PacketConn goroutine.
//  3. Close the C side of the socketpair (cFd) — fd is owned by Go end-to-end
//     when called from TsnetListenPacketClose; Swift must not call Darwin.close
//     on the same fd afterward.
//  4. Close pc outside the lock — unblocks pc.ReadFrom in the other goroutine
//     and synchronously releases the netstack port binding.
func (pl *packetListener) closeOnce() {
	pl.once.Do(func() {
		packetListeners.mu.Lock()
		delete(packetListeners.m, pl.cFd)
		_ = pl.pkt.Close()
		_ = closeBridgeCSide(pl.cFd)
		packetListeners.mu.Unlock()
		pl.pc.Close()
	})
}

//export TsnetListenPacket
func TsnetListenPacket(sd C.int, network, addr *C.char, listenerOut *C.int) C.int {
	s := getServer(sd)
	if s == nil {
		return C.EBADF
	}

	networkStr := C.GoString(network)
	pc, err := s.s.ListenPacket(networkStr, C.GoString(addr))
	if err != nil {
		return s.recErr(err)
	}
	s.started = true

	// Default datagram socket buffers are a few KB. RTP at 60fps with the
	// occasional keyframe burst will overflow that and the kernel will drop
	// datagrams silently. 4 MB on each side is roughly half a second of
	// 60Mbps video — enough headroom for a brief stall on the C side without
	// losing frames.
	const sockBuf = 4 * 1024 * 1024
	pkt, fdC, err := newBridgePacketPair(sockBuf)
	if err != nil {
		pc.Close()
		return s.recErr(err)
	}

	pl := &packetListener{s: s, pc: pc, pkt: pkt, cFd: fdC}
	packetListeners.mu.Lock()
	if packetListeners.m == nil {
		packetListeners.m = map[C.int]*packetListener{}
	}
	packetListeners.m[fdC] = pl
	packetListeners.mu.Unlock()

	// PacketConn → bridge. Read each tailnet datagram, prepend its source
	// address, write the framed message to the bridge as one datagram.
	// Closing pc (via pl.closeOnce) breaks the ReadFrom loop.
	go func() {
		defer pl.closeOnce()
		var buf [1 << 16]byte
		for {
			n, srcAddr, err := pc.ReadFrom(buf[:])
			if err != nil {
				return
			}
			addrStr := srcAddr.String()
			if len(addrStr) > 255 {
				// IP:port should never exceed 255 bytes; drop rather
				// than truncate to keep the framing unambiguous.
				continue
			}
			out := make([]byte, 1+len(addrStr)+n)
			out[0] = byte(len(addrStr))
			copy(out[1:], addrStr)
			copy(out[1+len(addrStr):], buf[:n])
			if _, err := pkt.Write(out); err != nil {
				return
			}
		}
	}()

	// bridge → PacketConn. Read each framed message from the C
	// side, resolve the destination address, write a UDP datagram. A
	// short read or zero-length read means the C side closed its fd.
	go func() {
		defer pl.closeOnce()
		var buf [1 << 16]byte
		for {
			n, err := pkt.Read(buf[:])
			if err != nil || n == 0 {
				return
			}
			if n < 1 {
				continue
			}
			addrLen := int(buf[0])
			if 1+addrLen > n {
				continue // malformed; drop
			}
			addrStr := string(buf[1 : 1+addrLen])
			payload := buf[1+addrLen : n]
			udpAddr, err := net.ResolveUDPAddr(networkStr, addrStr)
			if err != nil {
				continue // bad addr; UDP is lossy, drop and move on
			}
			// Best-effort send. WriteTo errors on a single datagram
			// (e.g. EHOSTUNREACH) shouldn't tear down the listener.
			pc.WriteTo(payload, udpAddr)
		}
	}()

	*listenerOut = fdC
	return 0
}

// TsnetListenPacketClose closes the UDP packet listener identified by fdC.
//
// Unlike the C side calling Darwin.close(fd), this function closes the
// listener synchronously: it calls pc.Close() on the underlying netstack
// PacketConn before returning, so the port is immediately available for a
// subsequent TsnetListenPacket call on the same address.
//
// It is safe to call concurrently with the bridge goroutines; sync.Once
// ensures the teardown body executes exactly once regardless of which caller
// arrives first.
//
// Returns 0 on success, EBADF if fdC is not a live packet listener.
//
//export TsnetListenPacketClose
func TsnetListenPacketClose(fdC C.int) C.int {
	packetListeners.mu.Lock()
	pl, ok := packetListeners.m[fdC]
	packetListeners.mu.Unlock()
	if !ok {
		return C.EBADF
	}
	pl.closeOnce()
	return 0
}
