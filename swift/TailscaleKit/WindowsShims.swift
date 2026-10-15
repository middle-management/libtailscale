// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Windows stand-ins for the POSIX calls the wrapper makes, mirroring
// GlibcShims.swift's role on Linux. On Apple platforms and Linux this file
// compiles to nothing.
//
// These are deliberately SOCKET calls, not CRT file calls. The descriptors the
// wrapper handles come from libtailscale's Go↔C bridge, which on Windows hands
// over a real Winsock SOCKET (see bridge_windows.go). The CRT's _read/_write
// don't work on sockets at all, and _close would close the wrong kind of
// handle — so read/write/close map to recv/send/closesocket.
//
// Likewise `poll` maps to WSAPoll rather than to any of the POSIX-looking
// entry points in Go's or the CRT's surface. Note that several Winsock
// wrappers elsewhere in this stack (syscall.Accept, Recvfrom, Sendto) compile
// on Windows but are EWINDOWS stubs that always fail at runtime; WSAPoll is a
// real call, which is why the whole poll path routes through it.
#if os(Windows)

import WinSDK

/// The wrapper's C API types descriptors as `Int32`, while Winsock's `SOCKET`
/// is a `UINT_PTR`. Handle values are 32-bit-significant, which the Windows
/// bridge spike asserts directly (`TestNativeHandleFitsInCInt`), so the
/// round-trip is lossless — but go through `bitPattern` rather than a plain
/// conversion so a negative sentinel can't trap.
@inline(__always)
private func sock(_ fd: Int32) -> SOCKET {
    SOCKET(UInt(bitPattern: Int(fd)))
}

enum Darwin {
    @discardableResult
    static func close(_ fd: Int32) -> Int32 {
        closesocket(sock(fd))
    }

    static func read(_ fd: Int32, _ buf: UnsafeMutableRawPointer?, _ count: Int) -> Int {
        guard let buf, count > 0 else { return 0 }
        let n = recv(sock(fd), buf.assumingMemoryBound(to: CChar.self), Int32(count), 0)
        return Int(n)
    }

    static func write(_ fd: Int32, _ buf: UnsafeRawPointer?, _ count: Int) -> Int {
        guard let buf, count > 0 else { return 0 }
        let n = send(
            sock(fd),
            UnsafeRawPointer(buf).assumingMemoryBound(to: CChar.self),
            Int32(count),
            0
        )
        return Int(n)
    }
}

/// POSIX-shaped `pollfd` so the call sites read identically on every platform.
/// `revents` is carried for completeness even though the wrapper only consults
/// `poll`'s return value today.
struct pollfd {
    var fd: Int32
    var events: Int16
    var revents: Int16

    init(fd: Int32, events: Int16, revents: Int16) {
        self.fd = fd
        self.events = events
        self.revents = revents
    }
}

/// WSAPoll signals readable data as POLLRDNORM; there is no separate POLLIN.
let POLLIN: Int32 = Int32(POLLRDNORM)

/// `poll(2)` over WSAPoll. Same contract: negative on error, 0 on timeout,
/// otherwise the number of ready descriptors.
func poll(_ fds: UnsafeMutablePointer<pollfd>, _ nfds: UInt32, _ timeout: Int32) -> Int32 {
    let count = Int(nfds)
    guard count > 0 else { return 0 }

    var wsaFds = (0..<count).map { i in
        WSAPOLLFD(fd: sock(fds[i].fd), events: fds[i].events, revents: 0)
    }
    let rc = WSAPoll(&wsaFds, nfds, timeout)
    for i in 0..<count {
        fds[i].revents = wsaFds[i].revents
    }
    return rc
}

#endif  // os(Windows)
