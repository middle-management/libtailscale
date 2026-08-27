// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Glibc stand-ins for the `Darwin.`-qualified syscalls the wrapper uses, so
// the same call sites compile on Linux. Internal on purpose: one shim serves
// every file in the module (extend it here, not per-file, when a new syscall
// needs qualifying). On Apple platforms this file compiles to nothing — the
// real Darwin module wins.
// Gated on Glibc rather than on "not Darwin": Windows is neither, and has its
// own stand-ins in WindowsShims.swift. `!canImport(Darwin)` silently assumed
// not-Darwin means Linux and broke the Windows build with `no such module
// 'Glibc'`.
#if canImport(Glibc)
import Glibc

enum Darwin {
    @discardableResult
    static func close(_ fd: Int32) -> Int32 { Glibc.close(fd) }
    static func read(_ fd: Int32, _ buf: UnsafeMutableRawPointer?, _ count: Int) -> Int {
        Glibc.read(fd, buf, count)
    }
    static func write(_ fd: Int32, _ buf: UnsafeRawPointer?, _ count: Int) -> Int {
        Glibc.write(fd, buf, count)
    }
}
#endif
