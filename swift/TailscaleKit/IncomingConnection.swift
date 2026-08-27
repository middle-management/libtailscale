// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

#if canImport(Combine)
import Combine
#endif
import Foundation
import libtailscale

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc

#endif

/// IncomingConnection is use to read incoming message from an inbound
/// connection.   IncomingConnections are not instantiated directly,
/// they are returned by Listener.accept
public actor IncomingConnection {
    private let logger: LogSink?
    private var conn: TailscaleConnection = 0
    private let reader: SocketReader

    public let remoteAddress: String?

#if canImport(Combine)
    @Published var _state: ConnectionState = .idle

    public func state() -> any AsyncSequence<ConnectionState, Never>  {
        $_state
            .removeDuplicates()
            .eraseToAnyPublisher()
            .values
    }
#else
    // Combine is Apple-only; AsyncStream provides the same
    // current-value-then-updates sequence on other platforms.
    var _state: ConnectionState = .idle {
        didSet {
            guard _state != oldValue else { return }
            for continuation in stateContinuations { continuation.yield(_state) }
        }
    }
    private var stateContinuations: [AsyncStream<ConnectionState>.Continuation] = []

    public func state() -> any AsyncSequence<ConnectionState, Never> {
        AsyncStream { continuation in
            continuation.yield(_state)
            stateContinuations.append(continuation)
        }
    }
#endif

    init(conn: TailscaleConnection, remoteAddress: String?, logger: LogSink? = nil) async {
        self.logger = logger
        self.conn = conn
        _state = .connected
        self.remoteAddress = remoteAddress
        reader = SocketReader(conn: conn)
    }

    deinit {
        if conn != 0 {
            Darwin.close(conn)
        }
    }

    public func close() {
        if conn != 0 {
            Darwin.close(conn)
            conn = 0
        }
        _state = .closed
    }

    /// Returns up to size bytes from the connection.  Blocks until
    /// data is available
    public func receive(maximumLength: Int = 4096, timeout: Int32) async throws -> Data {
        guard _state == .connected else {
            throw TailscaleError.connectionClosed
        }

        return try await reader.read(timeout: timeout, len: maximumLength)
    }

    /// Reads a complete message from the connection
    public func receiveMessage( timeout: Int32) async throws -> Data {
        guard _state == .connected else {
            throw TailscaleError.connectionClosed
        }

        return try await reader.readAll(timeout: timeout)
    }

    /// Sends the given data to the connection.
    /// Loops until every byte is written or an error is returned.
    public func send(_ data: Data) throws {
        guard _state == .connected else {
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
}

/// Serializes read operations from an IncomingConnection
private actor SocketReader {
    // We'll read in 2048 byte chunks which should be sufficient to hold the payload
    // of a single packet
    private static let maxBufferSize = 2048
    private let conn: TailscaleConnection
    private var buffer = [UInt8](repeating:0, count: maxBufferSize)

    init(conn: TailscaleConnection) {
        self.conn = conn
    }

    func read(timeout: Int32, len: Int) throws -> Data {
        var p: pollfd = .init(fd: conn, events: Int16(POLLIN), revents: 0)
        let res = poll(&p, 1, timeout)
        guard res > 0 else {
            throw TailscaleError.readFailed
        }

        let bytesToRead = min(len, Self.maxBufferSize)
        var bytesRead = 0
        buffer.withUnsafeMutableBufferPointer { ptr in
            bytesRead = Darwin.read(conn, ptr.baseAddress, bytesToRead)
        }

        if bytesRead < 0 {
            throw TailscaleError.readFailed
        }
        return Data(buffer[0..<bytesRead])
    }

    func readAll(timeout: Int32) throws -> Data {
        var data: Data = .init()
        while true {
            let read = try read(timeout: timeout, len: Self.maxBufferSize)
            data.append(read)
            if read.count < Self.maxBufferSize {
                break
            }
        }
        return data
    }
}

