// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The last error from a socket operation.
//
// This exists because `errno` is the wrong answer on Windows, not merely an
// unavailable one: Winsock reports failures through WSAGetLastError(), and
// `errno` would hold an unrelated (often stale, often zero) CRT value. Reading
// it there wouldn't fail to compile — it would quietly report the wrong error,
// which is worse.
#if os(Windows)
import WinSDK

var tailscaleLastSocketError: Int32 { WSAGetLastError() }
#elseif canImport(Darwin)
import Darwin

var tailscaleLastSocketError: Int32 { errno }
#else
import Glibc

var tailscaleLastSocketError: Int32 { errno }
#endif
