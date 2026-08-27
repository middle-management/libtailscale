// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Combine)
import Combine
#endif
import libtailscale

#if canImport(Darwin)
import Darwin
#else
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
    public func receive(maximumLength: Int = 65536, timeout: Int32) async throws -> Data {
        guard state == .connected else {
            throw TailscaleError.connectionClosed
        }

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
