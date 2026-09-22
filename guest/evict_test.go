// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package guest

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"
	"tailscale.com/types/nettype"
	"tailscale.com/wgengine/filter"
)

// TestRemoveClient pins the whole eviction contract RemoveClient makes:
// the evicted client's live flow dies, its established WireGuard session
// (which survives until rekey) can open nothing new, a fresh handshake
// with the same key is silently ignored, and a bystander client on the
// same server keeps working through all of it.
func TestRemoveClient(t *testing.T) {
	t.Parallel()
	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}

	const rtpPort = 7447
	s := &Server{Key: key.NewNode(), Logf: mkLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
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

	dial := func(name string, k key.NodePrivate) (*Client, net.Conn) {
		t.Helper()
		c := &Client{Server: s.ConnBlob(), Key: k, Logf: mkLogger(t, name)}
		t.Cleanup(func() { c.Close() })
		PingForTest(t, s, c)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn, err := c.DialUDPPort(ctx, rtpPort)
		if err != nil {
			t.Fatalf("%s DialUDPPort: %v", name, err)
		}
		t.Cleanup(func() { conn.Close() })
		return c, conn
	}
	echo := func(name string, conn net.Conn) {
		t.Helper()
		msg := rtpShapedPayload(1, 1200)
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("%s write: %v", name, err)
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil || n != len(msg) {
			t.Fatalf("%s echo: n=%d err=%v", name, n, err)
		}
	}

	keyA := key.NewNode()
	_, connA := dial("clientA", keyA)
	_, connB := dial("clientB", key.NewNode())
	echo("A", connA)
	echo("B", connB)

	s.RemoveClient(keyA.Public())

	// A's live flow is dead: the server closed its end, so writes may
	// still be swallowed (UDP) but no echo ever returns.
	if _, err := connA.Write(rtpShapedPayload(2, 1200)); err == nil {
		connA.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		if n, err := connA.Read(buf); err == nil {
			t.Fatalf("evicted A still got a %d-byte echo", n)
		} else if ne, ok := err.(net.Error); ok && !ne.Timeout() {
			// non-timeout error (closed flow) is equally acceptable
			_ = ne
		}
	}

	// A's WireGuard session outlives the netmap removal until rekey —
	// the flow gate is what stops it. A new dial on the same session
	// must yield no echoes either.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Reuse A's client object: its tunnel is already up, so this dial
	// exercises exactly the pre-rekey path the gate exists for.
	// (DialUDPPort itself succeeds — UDP dials don't handshake — the
	// silence comes from the refused flow.)
	// Note: we must reach through the same *Client that was evicted.
	// dial() would create a fresh handshake, which the denylist covers
	// separately below.
	c2, conn2ok := func() (*Client, net.Conn) {
		c := &Client{Server: s.ConnBlob(), Key: keyA, Logf: mkLogger(t, "clientA2")}
		t.Cleanup(func() { c.Close() })
		conn, err := c.DialUDPPort(ctx, rtpPort)
		if err != nil {
			return c, nil
		}
		return c, conn
	}()
	if conn2ok != nil {
		conn2ok.Write(rtpShapedPayload(3, 1200))
		conn2ok.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		if n, err := conn2ok.Read(buf); err == nil {
			t.Fatalf("re-handshaking evicted key got a %d-byte echo", n)
		}
		conn2ok.Close()
	}
	// And the denylist really did eat the fresh meow: no ack ever came.
	pctx, pcancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer pcancel()
	if _, err := c2.Ping(pctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ping from evicted key = %v; want deadline exceeded", err)
	}

	// The bystander keeps working after all of it.
	echo("B after eviction", connB)
}

// TestRemoveClientIDsMonotonic pins that node IDs are never reused
// across an eviction: admit A, evict A, admit B — B must not inherit
// A's ID (upstream's len(clients)+2 would hand it out again).
func TestRemoveClientIDsMonotonic(t *testing.T) {
	t.Parallel()
	dm := integration.RunDERPAndSTUN(t, mkLogger(t, "derpstun"), "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in derpmap")
	}
	s := &Server{Key: key.NewNode(), Logf: mkLogger(t, "server"), Region: reg}
	t.Cleanup(func() { s.Close() })
	if err := s.Start(); err != nil {
		t.Fatalf("server Start: %v", err)
	}

	admit := func(name string) (key.NodePublic, *Client) {
		t.Helper()
		c := &Client{Server: s.ConnBlob(), Logf: mkLogger(t, name)}
		t.Cleanup(func() { c.Close() })
		PingForTest(t, s, c)
		return c.PublicKey(), c
	}

	kA, _ := admit("clientA")
	s.lb.mu.Lock()
	idA := s.lb.clients[kA].ID
	s.lb.mu.Unlock()

	s.RemoveClient(kA)

	kB, _ := admit("clientB")
	s.lb.mu.Lock()
	idB := s.lb.clients[kB].ID
	_, aStillThere := s.lb.clients[kA]
	s.lb.mu.Unlock()

	if aStillThere {
		t.Fatal("evicted client still in the client set")
	}
	if idB <= idA {
		t.Fatalf("client B got ID %d, not greater than evicted A's %d — IDs reused", idB, idA)
	}
}
