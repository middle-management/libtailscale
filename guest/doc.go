// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package guest is a control-plane-free tsnet sibling: WireGuard tunnels
// over Tailscale's data plane (magicsock + DERP bootstrap + NAT traversal),
// addressed by an out-of-band connection token instead of a tailnet.
//
// Vendored from github.com/tailscale/tailcat at commit c04c5af (BSD-3, see
// guest/LICENSE), renamed from package tailcat, with local additions:
// UDP flows through the tunnel (tailcat is TCP-only). It exists to carry
// Tailscreen's share-by-token transport; see plans/share-by-token.md in
// middle-management/tailscreen.
package guest
