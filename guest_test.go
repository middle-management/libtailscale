// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"testing"

	"github.com/tailscale/libtailscale/guestctest"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/logger"
)

// TestGuestCAPI runs the guest_* C surface end to end — token → connect
// → 1200-byte UDP echo → evict → silence — against a local DERP/STUN
// harness, through the same cgo-export symbols the c-archive ships. The
// C half lives in guestctest (no `import "C"` in tests).
func TestGuestCAPI(t *testing.T) {
	logf := logger.Logf(func(format string, args ...any) {
		if !t.Failed() {
			t.Logf("[derpstun] "+format, args...)
		}
	})
	dm := integration.RunDERPAndSTUN(t, logf, "127.0.0.1")
	j, err := json.Marshal(dm)
	if err != nil {
		t.Fatal(err)
	}
	guestctest.RunTestGuest(t, string(j))

	// The C test closed everything; the handle maps must be empty.
	guestServers.mu.Lock()
	remS := len(guestServers.m)
	guestServers.mu.Unlock()
	guestClients.mu.Lock()
	remC := len(guestClients.m)
	guestClients.mu.Unlock()
	if remS > 0 || remC > 0 {
		t.Errorf("leaked handles: %d guest servers, %d guest clients", remS, remC)
	}
}
