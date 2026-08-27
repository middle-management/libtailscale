// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package guest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
	"tailscale.com/wgengine/filter"
)

// rtpShapedPayload builds an i-th test datagram shaped like Tailscreen's
// RTP: a 12-byte header (version bits, a payload type, a sequence number
// we assert ordering-agnostically on, a timestamp, an SSRC) followed by
// random payload bytes up to `size` total. Nothing parses it as RTP; the
// point is realistic datagram sizes (~1200 B, the media path's target)
// with per-packet identity so loss and corruption are distinguishable.
func rtpShapedPayload(i int, size int) []byte {
	b := make([]byte, size)
	b[0] = 0x80 // RTP version 2
	b[1] = 96   // PT 96, H.264 in Tailscreen's registry
	binary.BigEndian.PutUint16(b[2:], uint16(i))
	binary.BigEndian.PutUint32(b[4:], uint32(i)*3000)
	binary.BigEndian.PutUint32(b[8:], 0x7A115C4E)
	rand.Read(b[12:])
	return b
}

// runUDPThroughTunnel is the Phase 1 spike of plans/share-by-token.md
// (middle-management/tailscreen): prove that RTP-shaped datagrams flow
// both directions through a control-plane-free tunnel. The server echoes
// each datagram on the flow it arrived on; the client sends `count`
// datagrams of `size` bytes and requires every echo back, byte-identical.
// UDP under WireGuard loses nothing on loopback, so a missing echo is a
// wiring failure, not weather.
func runUDPThroughTunnel(t *testing.T, relayedOnly bool) {
	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	s := &Server{
		Key:                   key.NewNode(),
		Logf:                  mkLogger(t, "server"),
		Region:                reg,
		skipEndpointAdvertise: relayedOnly,
	}
	t.Cleanup(func() { s.Close() })

	const rtpPort = 7447
	s.ServedUDPPorts = []filter.PortRange{{First: rtpPort, Last: rtpPort}}
	s.OnUDP = func(port uint16) func(nettype.ConnPacketConn) {
		if port != rtpPort {
			return nil
		}
		return func(c nettype.ConnPacketConn) {
			defer c.Close()
			buf := make([]byte, 2048)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, err := c.Write(buf[:n]); err != nil {
					return
				}
			}
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	c := &Client{
		Server:                s.ConnBlob(),
		Logf:                  mkLogger(t, "client"),
		skipEndpointAdvertise: relayedOnly,
	}
	t.Cleanup(func() { c.Close() })

	pi := PingForTest(t, s, c)
	t.Logf("ping: %+v", pi)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := c.DialUDPPort(ctx, rtpPort)
	if err != nil {
		t.Fatalf("DialUDPPort: %v", err)
	}
	defer conn.Close()

	const (
		count = 32
		size  = 1200 // the media path's datagram target (see DatagramInbox)
	)
	sent := make(map[uint16][]byte, count)

	// Send and receive concurrently: the echo of datagram 0 can arrive
	// before datagram 31 is written, and a strict send-all-then-read
	// would need the tunnel to buffer the whole burst.
	errc := make(chan error, 1)
	go func() {
		for i := 0; i < count; i++ {
			p := rtpShapedPayload(i, size)
			sent[uint16(i)] = p
			if _, err := conn.Write(p); err != nil {
				errc <- err
				return
			}
		}
		errc <- nil
	}()

	got := make(map[uint16][]byte, count)
	buf := make([]byte, 2048)
	deadline := time.Now().Add(15 * time.Second)
	conn.SetReadDeadline(deadline)
	for len(got) < count {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read after %d/%d echoes: %v", len(got), count, err)
		}
		if n != size {
			t.Fatalf("echo size = %d, want %d", n, size)
		}
		seq := binary.BigEndian.Uint16(buf[2:])
		got[seq] = append([]byte(nil), buf[:n]...)
	}
	if err := <-errc; err != nil {
		t.Fatalf("send: %v", err)
	}
	for seq, p := range sent {
		if !bytes.Equal(got[seq], p) {
			t.Fatalf("datagram %d corrupted in transit", seq)
		}
	}

	// Confirm which path carried it. With endpoint advertisement off,
	// no direct path can ever be discovered, so the whole exchange above
	// was DERP-relayed — the browser-viewer/CGNAT-worst-case shape. With
	// it on (the default), loopback discovers a direct path; assert the
	// upgrade happened so the direct-path leg really is testing one.
	res, err := c.DiscoPing(ctx)
	if err != nil {
		t.Fatalf("DiscoPing: %v", err)
	}
	t.Logf("path: endpoint=%q derp=%q", res.Endpoint, res.DERPRegionCode)
	if relayedOnly && res.Endpoint != "" {
		t.Fatalf("relayed-only run found a direct path (%v); the skip hook is broken", res.Endpoint)
	}
	if !relayedOnly && res.Endpoint == "" {
		t.Fatalf("direct run stayed on DERP (%v); no direct path on loopback", res.DERPRegionCode)
	}
}

func TestUDPThroughTunnelDirect(t *testing.T) {
	t.Parallel()
	runUDPThroughTunnel(t, false)
}

func TestUDPThroughTunnelRelayed(t *testing.T) {
	t.Parallel()
	runUDPThroughTunnel(t, true)
}

// TestUDPRejectedPort pins the filter + handler gate: a flow to a port
// outside ServedUDPPorts must never reach OnUDP, and a datagram to it
// gets no reply (UDP has no RST; silence is the correct failure shape).
func TestUDPRejectedPort(t *testing.T) {
	t.Parallel()
	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}
	s := &Server{Key: key.NewNode(), Logf: mkLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })

	const servedPort = 7447
	s.ServedUDPPorts = []filter.PortRange{{First: servedPort, Last: servedPort}}
	handlerHit := make(chan uint16, 4)
	s.OnUDP = func(port uint16) func(nettype.ConnPacketConn) {
		handlerHit <- port
		if port != servedPort {
			return nil
		}
		return func(c nettype.ConnPacketConn) {
			defer c.Close()
			buf := make([]byte, 64)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				c.Write(buf[:n])
			}
		}
	}
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}
	c := &Client{Server: s.ConnBlob(), Logf: mkLogger(t, "client")}
	t.Cleanup(func() { c.Close() })
	PingForTest(t, s, c)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := c.DialUDPPort(ctx, servedPort+1)
	if err != nil {
		t.Fatalf("DialUDPPort: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("knock")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, err := conn.Read(buf); err == nil {
		t.Fatalf("got %d-byte reply on a filtered port; want silence", n)
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("read = %v; want timeout", err)
	}
	select {
	case p := <-handlerHit:
		t.Fatalf("OnUDP(%d) was called for a port the filter should have dropped", p)
	default:
	}
}
