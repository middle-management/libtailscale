// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The platform seam for the Go↔C socket bridge.
//
// tsnet connections are userspace-WireGuard conns with no OS descriptor, so
// libtailscale bridges each one to a real socket pair and hands C one end. On
// Unix that pair is socketpair(2) and accepted connections travel by SCM_RIGHTS
// (bridge_unix.go); on Windows neither primitive exists and both are emulated
// on the loopback interface (bridge_windows.go).
//
// Keeping the seam this narrow is deliberate: everything above it — the copy
// goroutines, the framing, the lifetime bookkeeping — is identical on both
// platforms and stays in tailscale.go.

package main

import "C"

import "io"

// bridgeConnSender is the extra capability the listener's control channel needs
// beyond plain I/O: handing an accepted connection's descriptor to the C
// consumer. On Unix that is an SCM_RIGHTS sendmsg; on Windows a plain record
// write, since both sides share one handle table.
//
// Kept separate from bridgeStream because only the listener pair needs it — the
// per-connection pairs in newConn never hand anything over.
type bridgeConnSender interface {
	bridgeStream
	sendConn(connFd C.int, addrBuf []byte) error
}

// bridgeStream is the Go end of a stream bridge pair.
//
// CloseRead/CloseWrite are half-close, used to propagate one direction of a
// tsnet connection ending without tearing down the other.
type bridgeStream interface {
	io.ReadWriteCloser
	CloseRead() error
	CloseWrite() error
}

// bridgePacket is the Go end of a datagram bridge pair. Message boundaries must
// be preserved: the UDP path frames each datagram as
// [1B addr_len][addr][payload] and relies on one write producing exactly one
// read.
type bridgePacket interface {
	io.ReadWriteCloser
}
