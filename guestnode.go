// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// The C surface of the guest (control-plane-free) backend: tokens in
// place of a tailnet, for Tailscreen's share-by-token feature. See
// guest/doc.go for what the backend is, and tailscale.h ("guest nodes")
// for the C API contract.
//
// Everything C-visible reuses the tsnet surface's bridge machinery so a
// consumer treats guest fds exactly like tsnet fds:
//
//   - guest_server_listen returns a listener consumed with
//     tailscale_accept / tailscale_getremoteaddr, via bridgeListen.
//   - guest_server_listen_packet and guest_client_dial_udp speak the
//     same [1B addr_len][addr][payload] datagram framing as
//     tailscale_listen_packet, so the Swift PacketListener needs no
//     guest-specific parsing.
//   - guest_client_dial returns a plain stream fd like tailscale_dial.
package main

//#include "errno.h"
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/tailscale/libtailscale/guest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
)

// guestServers tracks all allocated guest servers, keyed by the handle
// returned to C. A distinct handle range from tsnet's (42<<16+…) so a
// handle passed to the wrong family fails fast with EBADF.
var guestServers struct {
	mu   sync.Mutex
	next C.int
	m    map[C.int]*guestServer
}

type guestServer struct {
	gs *guest.Server
	// errSink records errors for guest_server_errmsg, and doubles as the
	// nil-tsnet *server that bridgeListen/newConn take for guest TCP.
	errSink *server

	mu       sync.Mutex
	started  bool
	closed   bool
	udpPorts map[uint16]*guestPacketBridge
	tcpPorts map[uint16]*chanListener
}

func getGuestServer(gd C.int) *guestServer {
	guestServers.mu.Lock()
	defer guestServers.mu.Unlock()
	return guestServers.m[gd]
}

//export GuestServerNew
func GuestServerNew() C.int {
	guestServers.mu.Lock()
	defer guestServers.mu.Unlock()
	if guestServers.m == nil {
		guestServers.m = map[C.int]*guestServer{}
	}
	if guestServers.next == 0 {
		guestServers.next = 47<<16 + 1
	}
	gd := guestServers.next
	guestServers.next++
	guestServers.m[gd] = &guestServer{
		gs:      &guest.Server{},
		errSink: &server{},
	}
	return gd
}

//export GuestServerSetDERPMapURL
func GuestServerSetDERPMapURL(gd C.int, url *C.char) C.int {
	g := getGuestServer(gd)
	if g == nil {
		return C.EBADF
	}
	g.gs.DERPMapURL = C.GoString(url)
	return 0
}

// GuestServerSetDERPMapJSON pins the bootstrap relay from a
// tailcfg.DERPMap JSON document instead of fetching a map from the
// network: the first region becomes the server's region, embedded in
// the token. This is how a self-hosted derper (or a test harness's
// local DERP) is supplied.
//
//export GuestServerSetDERPMapJSON
func GuestServerSetDERPMapJSON(gd C.int, dmJSON *C.char) C.int {
	g := getGuestServer(gd)
	if g == nil {
		return C.EBADF
	}
	var dm tailcfg.DERPMap
	if err := json.Unmarshal([]byte(C.GoString(dmJSON)), &dm); err != nil {
		return g.errSink.recErr(fmt.Errorf("guest: bad DERP map JSON: %w", err))
	}
	for _, r := range dm.Regions {
		g.gs.Region = r
		return 0
	}
	return g.errSink.recErr(fmt.Errorf("guest: DERP map JSON has no regions"))
}

//export GuestServerStart
func GuestServerStart(gd C.int) C.int {
	g := getGuestServer(gd)
	if g == nil {
		return C.EBADF
	}
	g.mu.Lock()
	if g.started {
		g.mu.Unlock()
		return 0
	}
	g.mu.Unlock()

	// Both dispatchers consult the per-port maps live, so listeners may
	// be registered before or after start.
	g.gs.OnUDP = func(port uint16) func(nettype.ConnPacketConn) {
		g.mu.Lock()
		pb := g.udpPorts[port]
		g.mu.Unlock()
		if pb == nil {
			return nil
		}
		return pb.handleFlow
	}
	g.gs.OnTCP = func(port uint16) func(net.Conn) {
		g.mu.Lock()
		cl := g.tcpPorts[port]
		g.mu.Unlock()
		if cl == nil {
			return nil
		}
		return cl.deliver
	}

	if err := g.gs.Start(); err != nil {
		return g.errSink.recErr(err)
	}
	g.mu.Lock()
	g.started = true
	g.mu.Unlock()
	return 0
}

// GuestServerToken writes the server's connection token — the string a
// viewer joins with — into buf. The token embeds the DERP region, so
// clients need no map fetch. Must be called after GuestServerStart.
//
//export GuestServerToken
func GuestServerToken(gd C.int, buf *C.char, buflen C.size_t) C.int {
	g := getGuestServer(gd)
	if g == nil {
		return C.EBADF
	}
	g.mu.Lock()
	started := g.started
	g.mu.Unlock()
	if !started {
		return g.errSink.recErr(fmt.Errorf("guest: server not started"))
	}
	return copyCString(string(g.gs.ConnBlob()), buf, buflen, g.errSink)
}

// GuestServerPeers writes a JSON array of the currently-admitted clients,
// [{"key":"nodekey:…","addr":"fd7a:…"}], in admission order. The addr is
// the source address the client's flows carry (guest.AddrForKey), which
// is how a consumer maps datagram sources back to identities.
//
//export GuestServerPeers
func GuestServerPeers(gd C.int, buf *C.char, buflen C.size_t) C.int {
	g := getGuestServer(gd)
	if g == nil {
		return C.EBADF
	}
	type peer struct {
		Key  string `json:"key"`
		Addr string `json:"addr"`
	}
	peers := []peer{} // "[]", never "null"
	for _, k := range g.gs.Clients() {
		peers = append(peers, peer{Key: k.String(), Addr: guest.AddrForKey(k).String()})
	}
	j, err := json.Marshal(peers)
	if err != nil {
		return g.errSink.recErr(err)
	}
	return copyCString(string(j), buf, buflen, g.errSink)
}

// GuestServerRemovePeer evicts the client whose node public key is
// nodeKey ("nodekey:<64 hex>", as GuestServerPeers reports it): its
// tunnel flows are closed and the key is denylisted for the life of
// this server. See guest.Server.RemoveClient.
//
//export GuestServerRemovePeer
func GuestServerRemovePeer(gd C.int, nodeKey *C.char) C.int {
	g := getGuestServer(gd)
	if g == nil {
		return C.EBADF
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(C.GoString(nodeKey))); err != nil {
		return g.errSink.recErr(fmt.Errorf("guest: bad node key: %w", err))
	}
	g.gs.RemoveClient(k)
	return 0
}

//export GuestServerErrmsg
func GuestServerErrmsg(gd C.int, buf *C.char, buflen C.size_t) C.int {
	g := getGuestServer(gd)
	if g == nil {
		return C.EBADF
	}
	return tsnetErrmsgInto(g.errSink, buf, buflen)
}

//export GuestServerClose
func GuestServerClose(gd C.int) C.int {
	guestServers.mu.Lock()
	g := guestServers.m[gd]
	delete(guestServers.m, gd)
	guestServers.mu.Unlock()
	if g == nil {
		return C.EBADF
	}
	g.mu.Lock()
	g.closed = true
	bridges := make([]*guestPacketBridge, 0, len(g.udpPorts))
	for _, pb := range g.udpPorts {
		bridges = append(bridges, pb)
	}
	lns := make([]*chanListener, 0, len(g.tcpPorts))
	for _, cl := range g.tcpPorts {
		lns = append(lns, cl)
	}
	g.udpPorts = nil
	g.tcpPorts = nil
	g.mu.Unlock()
	for _, pb := range bridges {
		pb.closeOnce()
	}
	for _, cl := range lns {
		cl.Close()
	}
	if err := g.gs.Close(); err != nil {
		return g.errSink.recErr(err)
	}
	return 0
}

// guestPacketBridge multiplexes every UDP flow to one served port over a
// single C-visible datagram fd, with the tsnet packet-listener framing:
// [1B addr_len][addr string][payload]. Inbound, addr is the client
// flow's remote address; outbound, the frame's addr picks which flow to
// write to (an unknown addr is dropped — UDP is lossy, and the flow may
// simply have closed).
type guestPacketBridge struct {
	pkt  bridgePacket
	cFd  C.int
	once sync.Once

	mu    sync.Mutex
	flows map[string]nettype.ConnPacketConn // remote "ip:port" → flow
}

func (pb *guestPacketBridge) closeOnce() {
	pb.once.Do(func() {
		pb.mu.Lock()
		flows := pb.flows
		pb.flows = nil
		pb.mu.Unlock()
		pb.pkt.Close()
		closeBridgeCSide(pb.cFd)
		for _, c := range flows {
			c.Close()
		}
	})
}

// handleFlow is the guest.Server OnUDP handler for one client flow: it
// registers the flow for outbound routing and pumps its datagrams to the
// bridge, framed with the flow's remote address.
func (pb *guestPacketBridge) handleFlow(c nettype.ConnPacketConn) {
	remote := c.RemoteAddr().String()
	if len(remote) > 255 {
		c.Close()
		return
	}
	pb.mu.Lock()
	if pb.flows == nil { // bridge already closed
		pb.mu.Unlock()
		c.Close()
		return
	}
	pb.flows[remote] = c
	pb.mu.Unlock()
	defer func() {
		pb.mu.Lock()
		if pb.flows != nil && pb.flows[remote] == c {
			delete(pb.flows, remote)
		}
		pb.mu.Unlock()
		c.Close()
	}()

	var buf [1 << 16]byte
	for {
		n, err := c.Read(buf[:])
		if err != nil {
			return
		}
		out := make([]byte, 1+len(remote)+n)
		out[0] = byte(len(remote))
		copy(out[1:], remote)
		copy(out[1+len(remote):], buf[:n])
		if _, err := pb.pkt.Write(out); err != nil {
			return
		}
	}
}

// GuestServerListenPacket serves UDP flows to the given port on the
// guest server's own tunnel address, multiplexed over one datagram fd
// with the tailscale_listen_packet framing. Register before or after
// GuestServerStart; one listener per port.
//
//export GuestServerListenPacket
func GuestServerListenPacket(gd C.int, port C.ushort, fdOut *C.int) C.int {
	g := getGuestServer(gd)
	if g == nil {
		return C.EBADF
	}
	const sockBuf = 4 * 1024 * 1024 // same headroom as TsnetListenPacket
	pkt, fdC, err := newBridgePacketPair(sockBuf)
	if err != nil {
		return g.errSink.recErr(err)
	}
	pb := &guestPacketBridge{pkt: pkt, cFd: fdC, flows: map[string]nettype.ConnPacketConn{}}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		pb.closeOnce()
		return C.EBADF
	}
	if g.udpPorts == nil {
		g.udpPorts = map[uint16]*guestPacketBridge{}
	}
	if _, dup := g.udpPorts[uint16(port)]; dup {
		g.mu.Unlock()
		pb.closeOnce()
		return g.errSink.recErr(fmt.Errorf("guest: port %d already has a packet listener", uint16(port)))
	}
	g.udpPorts[uint16(port)] = pb
	g.mu.Unlock()

	// Outbound pump: C frames → the flow the addr names. A zero-length
	// read means the C side closed its fd; unregister and tear down.
	go func() {
		defer func() {
			g.mu.Lock()
			if g.udpPorts[uint16(port)] == pb {
				delete(g.udpPorts, uint16(port))
			}
			g.mu.Unlock()
			pb.closeOnce()
		}()
		var buf [1 << 16]byte
		for {
			n, err := pb.pkt.Read(buf[:])
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
			addr := string(buf[1 : 1+addrLen])
			payload := buf[1+addrLen : n]
			pb.mu.Lock()
			c := pb.flows[addr]
			pb.mu.Unlock()
			if c == nil {
				continue // no such flow (evicted or gone); drop
			}
			c.Write(payload)
		}
	}()

	*fdOut = fdC
	return 0
}

// chanListener adapts guest.Server's callback-delivered TCP conns into a
// net.Listener so bridgeListen (and therefore tailscale_accept on the C
// side) can serve them unchanged.
type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
	addr netip.AddrPort
}

func (cl *chanListener) deliver(c net.Conn) {
	select {
	case cl.ch <- c:
	case <-cl.done:
		c.Close()
	}
}

func (cl *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-cl.ch:
		return c, nil
	case <-cl.done:
		return nil, net.ErrClosed
	}
}

func (cl *chanListener) Close() error {
	cl.once.Do(func() { close(cl.done) })
	return nil
}

func (cl *chanListener) Addr() net.Addr {
	return net.TCPAddrFromAddrPort(cl.addr)
}

// GuestServerListen serves TCP connections to the given port on the
// guest server's own tunnel address. The returned listener fd is
// consumed with tailscale_accept / tailscale_getremoteaddr, exactly
// like a tailscale_listen fd.
//
//export GuestServerListen
func GuestServerListen(gd C.int, port C.ushort, listenerOut *C.int) C.int {
	g := getGuestServer(gd)
	if g == nil {
		return C.EBADF
	}
	cl := &chanListener{ch: make(chan net.Conn), done: make(chan struct{})}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return C.EBADF
	}
	if g.tcpPorts == nil {
		g.tcpPorts = map[uint16]*chanListener{}
	}
	if _, dup := g.tcpPorts[uint16(port)]; dup {
		g.mu.Unlock()
		return g.errSink.recErr(fmt.Errorf("guest: port %d already has a listener", uint16(port)))
	}
	g.tcpPorts[uint16(port)] = cl
	g.mu.Unlock()

	ret := bridgeListen(g.errSink, cl, listenerOut)
	if ret != 0 {
		g.mu.Lock()
		if g.tcpPorts[uint16(port)] == cl {
			delete(g.tcpPorts, uint16(port))
		}
		g.mu.Unlock()
		cl.Close()
	}
	return ret
}

// guestClients tracks all allocated guest clients.
var guestClients struct {
	mu   sync.Mutex
	next C.int
	m    map[C.int]*guestClient
}

type guestClient struct {
	gc      *guest.Client
	errSink *server
}

func getGuestClient(cd C.int) *guestClient {
	guestClients.mu.Lock()
	defer guestClients.mu.Unlock()
	return guestClients.m[cd]
}

// GuestClientNew allocates a client for the given connection token. The
// tunnel comes up lazily on the first dial.
//
//export GuestClientNew
func GuestClientNew(token *C.char) C.int {
	guestClients.mu.Lock()
	defer guestClients.mu.Unlock()
	if guestClients.m == nil {
		guestClients.m = map[C.int]*guestClient{}
	}
	if guestClients.next == 0 {
		guestClients.next = 53<<16 + 1
	}
	cd := guestClients.next
	guestClients.next++
	guestClients.m[cd] = &guestClient{
		gc:      &guest.Client{Server: guest.ConnBlob(C.GoString(token))},
		errSink: &server{},
	}
	return cd
}

// guestDialTimeout bounds a client dial, which includes lazy tunnel
// bring-up: DERP connect, meow handshake, WireGuard handshake.
const guestDialTimeout = 30 * time.Second

// GuestClientDial opens a TCP connection to the given port on the
// server. The returned fd behaves exactly like a tailscale_dial fd.
//
//export GuestClientDial
func GuestClientDial(cd C.int, port C.ushort, connOut *C.int) C.int {
	c := getGuestClient(cd)
	if c == nil {
		return C.EBADF
	}
	ctx, cancel := context.WithTimeout(context.Background(), guestDialTimeout)
	defer cancel()
	netConn, err := c.gc.DialTCPPort(ctx, uint16(port))
	if err != nil {
		return c.errSink.recErr(err)
	}
	if err := newConn(c.errSink, netConn, connOut); err != nil {
		netConn.Close()
		return c.errSink.recErr(err)
	}
	return 0
}

// GuestClientDialUDP opens a connected UDP flow to the given port on the
// server, exposed as a datagram fd with the tailscale_listen_packet
// framing. Inbound frames carry the server's address; outbound frames'
// addresses are ignored (the flow has exactly one peer), so a consumer
// written against tailscale_listen_packet works unchanged.
//
//export GuestClientDialUDP
func GuestClientDialUDP(cd C.int, port C.ushort, fdOut *C.int) C.int {
	c := getGuestClient(cd)
	if c == nil {
		return C.EBADF
	}
	ctx, cancel := context.WithTimeout(context.Background(), guestDialTimeout)
	defer cancel()
	netConn, err := c.gc.DialUDPPort(ctx, uint16(port))
	if err != nil {
		return c.errSink.recErr(err)
	}
	remote := netConn.RemoteAddr().String()
	if len(remote) > 255 {
		netConn.Close()
		return c.errSink.recErr(fmt.Errorf("guest: remote addr too long"))
	}

	const sockBuf = 4 * 1024 * 1024
	pkt, fdC, err := newBridgePacketPair(sockBuf)
	if err != nil {
		netConn.Close()
		return c.errSink.recErr(err)
	}
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			pkt.Close()
			closeBridgeCSide(fdC)
			netConn.Close()
		})
	}
	// Flow → bridge, framed with the server's address.
	go func() {
		defer closeAll()
		var buf [1 << 16]byte
		for {
			n, err := netConn.Read(buf[:])
			if err != nil {
				return
			}
			out := make([]byte, 1+len(remote)+n)
			out[0] = byte(len(remote))
			copy(out[1:], remote)
			copy(out[1+len(remote):], buf[:n])
			if _, err := pkt.Write(out); err != nil {
				return
			}
		}
	}()
	// Bridge → flow; the frame's address is ignored (single peer).
	go func() {
		defer closeAll()
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
			netConn.Write(buf[1+addrLen : n])
		}
	}()
	*fdOut = fdC
	return 0
}

//export GuestClientErrmsg
func GuestClientErrmsg(cd C.int, buf *C.char, buflen C.size_t) C.int {
	c := getGuestClient(cd)
	if c == nil {
		return C.EBADF
	}
	return tsnetErrmsgInto(c.errSink, buf, buflen)
}

//export GuestClientClose
func GuestClientClose(cd C.int) C.int {
	guestClients.mu.Lock()
	c := guestClients.m[cd]
	delete(guestClients.m, cd)
	guestClients.mu.Unlock()
	if c == nil {
		return C.EBADF
	}
	if err := c.gc.Close(); err != nil {
		return c.errSink.recErr(err)
	}
	return 0
}

// copyCString copies s (with its NUL) into a C buffer, recording an
// error on sink if the buffer is too small.
func copyCString(s string, buf *C.char, buflen C.size_t, sink *server) C.int {
	if buf == nil || buflen == 0 {
		return C.EINVAL
	}
	if int(buflen) < len(s)+1 {
		return sink.recErr(fmt.Errorf("guest: buffer too small: need %d, have %d", len(s)+1, int(buflen)))
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)
	copy(out, s)
	out[len(s)] = 0
	return 0
}

// tsnetErrmsgInto writes sink's last error into a C buffer with
// TsnetErrmsg's exact truncation/NUL semantics.
func tsnetErrmsgInto(sink *server, buf *C.char, buflen C.size_t) C.int {
	if buf == nil || buflen == 0 {
		return C.EINVAL
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), buflen)
	n := copy(out, sink.lastErr)
	if n >= len(out) {
		out[len(out)-1] = 0 // always NUL-terminate
		return C.ERANGE
	}
	out[n] = 0
	return 0
}
