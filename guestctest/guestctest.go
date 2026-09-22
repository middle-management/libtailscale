// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package guestctest tests the guest_* C bindings end to end: token →
// connect → UDP echo → evict, through the real C API over a real
// (locally-relayed) tunnel. It is driven by guest_test.go in the root
// package, which supplies a local DERP/STUN harness as a DERP-map JSON —
// the same reason tsnetctest exists: 'import "C"' is not allowed in
// tests, so the C-calling half lives here.
package guestctest

/*
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../tailscale.h"

static int errlen = 512;
char gerr[512]; // not static: referenced from Go as C.gerr

static guest_server gs;
static guest_client gc;

static int set_gs_err(char tag) {
	gerr[0] = tag; gerr[1] = ':'; gerr[2] = ' ';
	guest_server_errmsg(gs, &gerr[3], errlen-3);
	return 1;
}
static int set_gc_err(char tag) {
	gerr[0] = tag; gerr[1] = ':'; gerr[2] = ' ';
	guest_client_errmsg(gc, &gerr[3], errlen-3);
	return 1;
}

// read_frame reads one [1B addr_len][addr][payload] datagram from fd with
// a poll timeout, splitting it into addr (NUL-terminated, cap 256) and
// payload. Returns payload length, 0 on timeout, -1 on error.
static ssize_t read_frame(int fd, int timeout_ms, char* addr, char* payload, size_t paylen) {
	struct pollfd p = { .fd = fd, .events = POLLIN };
	int pr = poll(&p, 1, timeout_ms);
	if (pr == 0) return 0;
	if (pr < 0) return -1;
	char buf[65536];
	ssize_t n = read(fd, buf, sizeof(buf));
	if (n <= 1) return -1;
	int alen = (unsigned char)buf[0];
	if (1 + alen > n) return -1;
	memcpy(addr, &buf[1], alen); addr[alen] = 0;
	ssize_t plen = n - 1 - alen;
	if ((size_t)plen > paylen) return -1;
	memcpy(payload, &buf[1+alen], plen);
	return plen;
}

// write_frame writes one framed datagram to fd.
static ssize_t write_frame(int fd, const char* addr, const char* payload, size_t paylen) {
	char buf[65536];
	size_t alen = strlen(addr);
	if (alen > 255 || 1 + alen + paylen > sizeof(buf)) return -1;
	buf[0] = (char)alen;
	memcpy(&buf[1], addr, alen);
	memcpy(&buf[1+alen], payload, paylen);
	return write(fd, buf, 1 + alen + paylen);
}

// test_guest runs the whole flow. Returns 0 on success; on failure gerr
// holds a tagged message.
static int test_guest(const char* dm_json) {
	int ret;
	gs = guest_server_new();
	if ((ret = guest_server_set_derpmap_json(gs, dm_json)) != 0) {
		return set_gs_err('0');
	}
	if ((ret = guest_server_start(gs)) != 0) {
		return set_gs_err('1');
	}
	char token[1024];
	if ((ret = guest_server_token(gs, token, sizeof(token))) != 0) {
		return set_gs_err('2');
	}

	tailscale_listener sfd;
	if ((ret = guest_server_listen_packet(gs, 7447, &sfd)) != 0) {
		return set_gs_err('3');
	}

	gc = guest_client_new(token);
	tailscale_listener cfd;
	if ((ret = guest_client_dial_udp(gc, 7447, &cfd)) != 0) {
		return set_gc_err('4');
	}

	// Client → server: an RTP-sized datagram (1200 bytes, tagged head).
	char want[1200];
	memset(want, 0x5A, sizeof(want));
	memcpy(want, "rtp-shaped-datagram", 19);
	if (write_frame(cfd, "x", want, sizeof(want)) < 0) {
		snprintf(gerr, errlen, "5: client write: errno %d (%s)", errno, strerror(errno));
		return 1;
	}

	// Server receives it, learns the client's flow address from the frame.
	char client_addr[256], got[65536];
	ssize_t n = read_frame(sfd, 30000, client_addr, got, sizeof(got));
	if (n != (ssize_t)sizeof(want) || memcmp(got, want, sizeof(want)) != 0) {
		snprintf(gerr, errlen, "6: server read_frame = %zd (errno %d)", n, errno);
		return 1;
	}

	// Server → client: echo it back to that address.
	if (write_frame(sfd, client_addr, want, sizeof(want)) < 0) {
		snprintf(gerr, errlen, "7: server write: errno %d (%s)", errno, strerror(errno));
		return 1;
	}
	char server_addr[256];
	n = read_frame(cfd, 30000, server_addr, got, sizeof(got));
	if (n != (ssize_t)sizeof(want) || memcmp(got, want, sizeof(want)) != 0) {
		snprintf(gerr, errlen, "8: client read_frame = %zd (errno %d)", n, errno);
		return 1;
	}

	// The address the token predicts must be the address the frames carry
	// (Swift's viewer filters inbound datagrams on exactly this match).
	char predicted[256];
	if ((ret = guest_client_server_addr(gc, predicted, sizeof(predicted))) != 0) {
		return set_gc_err('i');
	}
	if (strncmp(server_addr, "[", 1) == 0
			? strncmp(&server_addr[1], predicted, strlen(predicted)) != 0
			: strncmp(server_addr, predicted, strlen(predicted)) != 0) {
		snprintf(gerr, errlen, "j: predicted server addr %s, frames carry %s", predicted, server_addr);
		return 1;
	}

	// One admitted peer; pull its node key out of the JSON.
	char peers[2048];
	if ((ret = guest_server_peers(gs, peers, sizeof(peers))) != 0) {
		return set_gs_err('9');
	}
	char* keyp = strstr(peers, "nodekey:");
	if (!keyp) {
		snprintf(gerr, errlen, "a: no nodekey in peers: %s", peers);
		return 1;
	}
	char nodekey[128];
	size_t ki = 0;
	while (keyp[ki] && keyp[ki] != '"' && ki < sizeof(nodekey)-1) {
		nodekey[ki] = keyp[ki];
		ki++;
	}
	nodekey[ki] = 0;

	// Evict, and prove the tunnel actually closed: further client
	// datagrams produce no echo (2s of silence), and the peer list
	// empties.
	if ((ret = guest_server_remove_peer(gs, nodekey)) != 0) {
		return set_gs_err('b');
	}
	write_frame(cfd, "x", want, sizeof(want)); // may fail; flow is dying
	// Eviction stops NEW traffic; a datagram already in flight when the
	// flow closed may still land. Drain that race for up to a second,
	// then require a full 2s of silence.
	while (read_frame(sfd, 1000, client_addr, got, sizeof(got)) > 0) {
	}
	if ((n = read_frame(sfd, 2000, client_addr, got, sizeof(got))) > 0) {
		snprintf(gerr, errlen, "c: server got %zd-byte datagram after evict settled", n);
		return 1;
	}
	if ((ret = guest_server_peers(gs, peers, sizeof(peers))) != 0) {
		return set_gs_err('d');
	}
	if (strstr(peers, "nodekey:")) {
		snprintf(gerr, errlen, "e: peers not empty after evict: %s", peers);
		return 1;
	}

	if ((ret = guest_client_close(gc)) != 0) {
		return set_gc_err('f');
	}
	if ((ret = close(cfd)) != 0 && errno != EBADF) {
		snprintf(gerr, errlen, "g: close(cfd): errno %d", errno);
		return 1;
	}
	if ((ret = guest_server_close(gs)) != 0) {
		return set_gs_err('h');
	}
	return 0;
}
*/
import "C"

import (
	"testing"
	"unsafe"
)

// RunTestGuest drives the C-side test_guest against a DERP map JSON
// (a local test relay from the caller).
func RunTestGuest(t *testing.T, dmJSON string) {
	cs := C.CString(dmJSON)
	defer C.free(unsafe.Pointer(cs))
	if C.test_guest(cs) != 0 {
		t.Fatalf("guest ctest: %s", C.GoString(&C.gerr[0]))
	}
}
