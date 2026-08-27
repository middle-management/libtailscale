// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Combine)
import Combine
#endif
#if canImport(libtailscale)
import libtailscale
#endif

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc

#endif

/// ConnectionState indicates the state of individual TSConnection instances
public enum ConnectionState: Sendable {
    case idle           ///< Reads and writes are not possible.  Connections will transition to connected automatically
    case connected      ///< Connected and ready to read/write
    case closed         ///< Closed and ready to be disposed of.  Closed connections cannot be reconnected.
    case failed         ///< The attempt to dial the connection failed
}

/// ListenerState indicates the state of individual TSListener instances
public enum ListenerState: Sendable {
    case idle           ///< Waiting.
    case listening      ///< Listening
    case closed         ///< Closed and ready to be disposed of.
    case failed         ///< The attempt to start the listener failed
}

public typealias TailscaleHandle = Int32
public typealias TailscaleConnection = Int32
public typealias TailscaleListener = Int32

/// Outgoing connections are used to send data to other endpoints
/// on the tailnet.
///
/// For HTTP(s), consider using URLSession.tailscaleSession
public actor OutgoingConnection {
    private var tailscale: TailscaleHandle
    private var proto: NetProtocol
    private var address: String
    private var conn: TailscaleConnection = 0

    /// Owns the blocking poll+read so `receive` does NOT run it under this
    /// actor's isolation. See `receive` for why that matters.
    private var reader: OutgoingSocketReader?

    private let logger: LogSink

    /// The state of the connection.  Listen for transitions to determine
    /// if the connection may be used for send/receive operations.
    public var state: ConnectionState = .idle

    /// Creates a new outgoing connection
    ///
    /// @param tailscale The tailscale Server to use
    /// @param address The remote address and port
    /// @param proto The ip protocol
    /// @param logger
    ///
    /// @throws TailscaleError on failure
    public init(tailscale: TailscaleHandle,
         to address: String,
         proto: NetProtocol,
         logger: LogSink) async throws {

        self.logger = logger
        self.proto = proto
        self.address = address
        self.tailscale = tailscale
    }

    /// Connects the outgoing connection to the remote.  On success, the
    /// connection state will be .connected.
    ///
    /// @See tailscale_dial in Tailscale.h
    ///
    /// @throws TailscaleError on failure
    public func connect() async throws  {
        let res = tailscale_dial(tailscale, proto.rawValue, address, &conn)

        guard res == 0 else {
            self.state = .failed
            throw TailscaleError.fromPosixErrCode(res, tailscale.getErrorMessage())
        }

        self.state = .connected
        self.reader = OutgoingSocketReader(conn: conn)
    }

    deinit {
        if conn != 0 {
            Darwin.close(conn)
        }
    }

    /// Closes the outgoing connection.  Further sends are not possible.
    /// Connections will be closed on deallocation.  Sets the connection
    /// state to .closed
    public func close() {
        if conn != 0 {
            Darwin.close(conn)
            conn = 0
        }
        reader = nil
        state = .closed
    }

    /// Sends the given data to the connection.
    /// Loops until every byte is written or an error is returned — a single
    /// write(2) may legitimately be short (socketpair buffers are a few KB),
    /// which is not a failure. Mirrors IncomingConnection.send.
    public func send(_ data: Data) throws {
        guard state == .connected else {
            throw TailscaleError.connectionClosed
        }

        try data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) in
            guard var ptr = buffer.baseAddress else { return }
            var remaining = buffer.count
            while remaining > 0 {
                let written = Darwin.write(conn, ptr, remaining)
                if written <= 0 {
                    throw TailscaleError.shortWrite
                }
                remaining -= written
                ptr = ptr.advanced(by: written)
            }
        }
    }

    /// Returns up to `maximumLength` bytes from the connection. Blocks until data is
    /// available or `timeout` (ms) elapses.
    ///
    /// The poll+read runs on a SEPARATE actor (`OutgoingSocketReader`) rather
    /// than inline here, and that is the whole point of this method's shape.
    /// `poll(2)` blocks for the full timeout when the peer is quiet, and a
    /// receive loop typically passes a multi-second timeout. Running it under
    /// *this* actor's isolation holds the connection's executor for that whole
    /// interval, so every concurrent `send` on the same connection queues
    /// behind it — a caller that reads on one task and writes on another (the
    /// normal shape of a duplex control channel) sees its writes delayed by up
    /// to one poll interval. Awaiting a second actor suspends `receive` and
    /// releases this one, so sends interleave with a blocked read.
    ///
    /// Mirrors `IncomingConnection`, which already separates its reader for
    /// the same reason.
    public func receive(maximumLength: Int = 65536, timeout: Int32) async throws -> Data {
        guard state == .connected, let reader else {
            throw TailscaleError.connectionClosed
        }

        return try await reader.read(maximumLength: maximumLength, timeout: timeout)
    }
}

/// Serializes reads on an `OutgoingConnection`, off the connection actor.
///
/// Holds the fd by value: a `close()` on the connection makes the next
/// `poll`/`read` here fail, which surfaces as `readFailed` and unwinds the
/// caller's receive loop — the same teardown path a peer disconnect takes.
private actor OutgoingSocketReader {
    private let conn: TailscaleConnection

    init(conn: TailscaleConnection) {
        self.conn = conn
    }

    func read(maximumLength: Int, timeout: Int32) throws -> Data {
        var p: pollfd = .init(fd: conn, events: Int16(POLLIN), revents: 0)
        let res = poll(&p, 1, timeout)
        guard res > 0 else {
            throw TailscaleError.readFailed
        }

        var buffer = [UInt8](repeating: 0, count: maximumLength)
        let bytesRead = buffer.withUnsafeMutableBufferPointer { Darwin.read(conn, $0.baseAddress, maximumLength) }
        if bytesRead <= 0 {
            throw TailscaleError.readFailed
        }
        return Data(buffer[0..<bytesRead])
    }
}
