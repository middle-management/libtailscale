// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc

#endif
#if canImport(CGoRuntimeInit)
import CGoRuntimeInit
#endif
import Foundation
#if canImport(libtailscale)
import libtailscale
#endif

/// Guest nodes: control-plane-free tunnels addressed by a connection
/// token instead of a tailnet (see "guest nodes" in tailscale.h and the
/// guest/ Go package). A ``GuestServerNode`` hands out one token; any
/// ``GuestClientNode`` holding it can knock. The listeners and
/// connections these vend are the ordinary TailscaleKit types —
/// ``PacketListener``, ``Listener``, ``IncomingConnection`` — because
/// the C surface keeps guest fds bit-compatible with tsnet fds.

/// One admitted guest client, as reported by ``GuestServerNode/peers()``.
public struct GuestPeer: Codable, Sendable, Equatable {
    /// The client's WireGuard node public key ("nodekey:…") — its
    /// cryptographic identity, and the value ``GuestServerNode/removePeer(key:)``
    /// takes.
    public let key: String
    /// The tunnel address the client's flows carry as their source —
    /// what a `PacketListener.recv` reports in `from` (without the port).
    public let addr: String
}

/// A control-plane-free server node: shares out over one ephemeral token.
///
/// The node key is generated fresh at start and never persisted, so the
/// token dies with ``close()`` — exactly the lifetime a one-off share
/// link wants. There is no sign-in and no tailnet; admission control is
/// the caller's (approve/deny per peer, ``removePeer(key:)`` to evict).
public actor GuestServerNode {
    private var handle: Int32
    private let logger: LogSink?

    /// Creates the server (not yet started).
    ///
    /// @param derpMapURL Optional URL to fetch the DERP map from at start.
    /// @param derpMapJSON Optional tailcfg.DERPMap JSON pinning the
    ///        bootstrap relay directly (first region wins) — how a
    ///        self-hosted derper is supplied. Takes precedence.
    /// @param logger An optional LogSink.
    public init(derpMapURL: String? = nil,
                derpMapJSON: String? = nil,
                logger: LogSink? = nil) throws {
        // Same reason TailscaleNode.init calls this: the Go runtime in
        // libtailscale.a must be running before the first call into it,
        // and on Windows nothing else starts it. Idempotent, no-op on
        // Darwin/Linux.
        ts_go_runtime_start()
        self.logger = logger
        self.handle = guest_server_new()
        if let url = derpMapURL {
            let res = guest_server_set_derpmap_url(handle, url)
            guard res == 0 else {
                throw TailscaleError.fromPosixErrCode(res, handle.getErrorMessage())
            }
        }
        if let json = derpMapJSON {
            let res = guest_server_set_derpmap_json(handle, json)
            guard res == 0 else {
                throw TailscaleError.fromPosixErrCode(res, handle.getErrorMessage())
            }
        }
    }

    deinit {
        if handle != 0 {
            guest_server_close(handle)
        }
    }

    /// Connects to the DERP relay and begins accepting clients. Blocks
    /// for the relay bootstrap (network).
    public func start() throws {
        let res = guest_server_start(handle)
        guard res == 0 else {
            let msg = handle.getErrorMessage()
            logger?.log("GuestServerNode start failed: \(msg)")
            throw TailscaleError.fromPosixErrCode(res, msg)
        }
        logger?.log("GuestServerNode started")
    }

    /// The connection token — the string a viewer joins with. It embeds
    /// the DERP relay details, so a client needs no map fetch. Only
    /// valid after ``start()``.
    public func token() throws -> String {
        let cap = 1024
        let buf = UnsafeMutablePointer<Int8>.allocate(capacity: cap)
        defer { buf.deallocate() }
        let res = guest_server_token(handle, buf, cap)
        guard res == 0 else {
            throw TailscaleError.fromPosixErrCode(res, handle.getErrorMessage())
        }
        return String(cString: buf)
    }

    /// Serves UDP flows to `port` on this node's own tunnel address. The
    /// returned ``PacketListener`` speaks the standard framed-datagram
    /// protocol: each `recv` reports the sending client's tunnel address,
    /// and `send(_:to:)` routes by that address — so the share pipeline's
    /// existing fan-out code works unchanged.
    public func listenPacket(port: UInt16) throws -> PacketListener {
        var fd: TailscaleListener = 0
        let res = guest_server_listen_packet(handle, port, &fd)
        guard res == 0 else {
            throw TailscaleError.fromPosixErrCode(res, handle.getErrorMessage())
        }
        return PacketListener(adopting: fd, handle: handle,
                              address: "guest:\(port)", logger: logger)
    }

    /// Serves TCP connections to `port` on this node's own tunnel
    /// address. The returned ``Listener`` accepts with the same machinery
    /// as a tsnet listener (`tailscale_accept`), so the framed control
    /// channel's code works unchanged.
    public func listen(port: UInt16) async throws -> Listener {
        var fd: TailscaleListener = 0
        let res = guest_server_listen(handle, port, &fd)
        guard res == 0 else {
            throw TailscaleError.fromPosixErrCode(res, handle.getErrorMessage())
        }
        return await Listener(adopting: fd, handle: handle,
                              address: "guest:\(port)", logger: logger)
    }

    /// The currently-admitted clients, in admission order.
    public func peers() throws -> [GuestPeer] {
        let cap = 64 * 1024
        let buf = UnsafeMutablePointer<Int8>.allocate(capacity: cap)
        defer { buf.deallocate() }
        let res = guest_server_peers(handle, buf, cap)
        guard res == 0 else {
            throw TailscaleError.fromPosixErrCode(res, handle.getErrorMessage())
        }
        let json = String(cString: buf)
        guard let data = json.data(using: .utf8) else {
            throw TailscaleError.internalError("guest peers JSON not UTF-8")
        }
        return try JSONDecoder().decode([GuestPeer].self, from: data)
    }

    /// Evicts the client with the given node public key (``GuestPeer/key``):
    /// its tunnel flows close now, and the key is refused for the life of
    /// this server. Re-admission requires a new server — a new share.
    public func removePeer(key: String) throws {
        let res = guest_server_remove_peer(handle, key)
        guard res == 0 else {
            throw TailscaleError.fromPosixErrCode(res, handle.getErrorMessage())
        }
        logger?.log("GuestServerNode evicted \(key)")
    }

    /// Shuts the node down: all clients drop, all vended listeners die,
    /// and the token is dead forever. The node cannot be restarted.
    public func close() {
        if handle != 0 {
            guest_server_close(handle)
            handle = 0
        }
    }
}

/// A control-plane-free client node: joins a share by its token.
///
/// The tunnel comes up lazily on the first dial (DERP connect, handshake
/// with the server, NAT traversal in the background), so `dial*` can
/// block for tens of seconds on first use.
public actor GuestClientNode {
    private var handle: Int32
    private let logger: LogSink?

    public init(token: String, logger: LogSink? = nil) {
        ts_go_runtime_start()
        self.logger = logger
        self.handle = guest_client_new(token)
    }

    deinit {
        if handle != 0 {
            guest_client_close(handle)
        }
    }

    /// The server's tunnel address (bare IP, no port) — the source
    /// address inbound datagram frames on this client's flows carry,
    /// derived from the token's embedded server key. No network touched.
    public func serverAddr() throws -> String {
        let cap = 256
        let buf = UnsafeMutablePointer<Int8>.allocate(capacity: cap)
        defer { buf.deallocate() }
        let res = guest_client_server_addr(handle, buf, cap)
        guard res == 0 else {
            throw TailscaleError.fromPosixErrCode(res, handle.getErrorMessage())
        }
        return String(cString: buf)
    }

    /// Opens a connected UDP flow to `port` on the server, as a
    /// ``PacketListener``: `recv` reports the server's tunnel address as
    /// the source, and `send(_:to:)` accepts any address (the flow has
    /// exactly one peer). This is the viewer's media socket.
    public func dialUDP(port: UInt16) throws -> PacketListener {
        var fd: TailscaleListener = 0
        let res = guest_client_dial_udp(handle, port, &fd)
        guard res == 0 else {
            let msg = handle.getErrorMessage()
            logger?.log("GuestClientNode dialUDP failed: \(msg)")
            throw TailscaleError.fromPosixErrCode(res, msg)
        }
        return PacketListener(adopting: fd, handle: handle,
                              address: "guest-dial:\(port)", logger: logger)
    }

    /// Opens a TCP connection to `port` on the server. The returned
    /// connection sends and receives like any accepted tsnet connection;
    /// this is the viewer's framed control channel.
    public func dial(port: UInt16) async throws -> IncomingConnection {
        var fd: TailscaleConnection = 0
        let res = guest_client_dial(handle, port, &fd)
        guard res == 0 else {
            let msg = handle.getErrorMessage()
            logger?.log("GuestClientNode dial failed: \(msg)")
            throw TailscaleError.fromPosixErrCode(res, msg)
        }
        return await IncomingConnection(conn: fd, remoteAddress: nil, logger: logger)
    }

    /// Tears the tunnel down. The node cannot be reused.
    public func close() {
        if handle != 0 {
            guest_client_close(handle)
            handle = 0
        }
    }
}
