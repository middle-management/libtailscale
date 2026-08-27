// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

#include "tailscale.h"
#include <stdio.h>

// These are unused by this file — every function below is a pass-through to an
// exported Go symbol — but they are POSIX-only and would fail the Windows
// build outright. Kept behind a guard rather than deleted so a future addition
// that does need them on Unix still finds them where it expects.
#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

// Functions exported by Go.
extern int TsnetNewServer();
extern int TsnetStart(int sd);
extern int TsnetUp(int sd);
extern int TsnetClose(int sd);
extern int TsnetErrmsg(int sd, char* buf, size_t buflen);
extern int TsnetDial(int sd, char* net, char* addr, int* connOut);
extern int TsnetSetDir(int sd, char* str);
extern int TsnetSetHostname(int sd, char* str);
extern int TsnetSetAuthKey(int sd, char* str);
extern int TsnetSetControlURL(int sd, char* str);
extern int TsnetSetEphemeral(int sd, int ephemeral);
extern int TsnetSetLogFD(int sd, int fd);
extern int TsnetGetIps(int sd, char *buf, size_t buflen);
extern int TsnetGetRemoteAddr(int listener, int conn, char *buf, size_t buflen);
extern int TsnetListen(int sd, char* net, char* addr, int* listenerOut);
extern int TsnetAccept(int ld, int* connOut);
extern int TsnetListenPacket(int sd, char* net, char* addr, int* listenerOut);
extern int TsnetListenPacketClose(int fd);
extern int TsnetLoopback(int sd, char* addrOut, size_t addrLen, char* proxyOut, char* localOut);
extern int TsnetEnableFunnelToLocalhostPlaintextHttp1(int sd, int localhostPort);
extern int GuestServerNew();
extern int GuestServerSetDERPMapURL(int gd, char* url);
extern int GuestServerSetDERPMapJSON(int gd, char* dmJSON);
extern int GuestServerStart(int gd);
extern int GuestServerToken(int gd, char* buf, size_t buflen);
extern int GuestServerListenPacket(int gd, unsigned short port, int* fdOut);
extern int GuestServerListen(int gd, unsigned short port, int* listenerOut);
extern int GuestServerPeers(int gd, char* buf, size_t buflen);
extern int GuestServerRemovePeer(int gd, char* nodeKey);
extern int GuestServerErrmsg(int gd, char* buf, size_t buflen);
extern int GuestServerClose(int gd);
extern int GuestClientNew(char* token);
extern int GuestClientDial(int cd, unsigned short port, int* connOut);
extern int GuestClientDialUDP(int cd, unsigned short port, int* fdOut);
extern int GuestClientServerAddr(int cd, char* buf, size_t buflen);
extern int GuestClientErrmsg(int cd, char* buf, size_t buflen);
extern int GuestClientClose(int cd);

tailscale tailscale_new() {
	return TsnetNewServer();
}

int tailscale_start(tailscale sd) {
	return TsnetStart(sd);
}

int tailscale_up(tailscale sd) {
	return TsnetUp(sd);
}

int tailscale_close(tailscale sd) {
	return TsnetClose(sd);
}

int tailscale_dial(tailscale sd, const char* network, const char* addr, tailscale_conn* conn_out) {
	return TsnetDial(sd, (char*)network, (char*)addr, (int*)conn_out);
}

int tailscale_listen(tailscale sd, const char* network, const char* addr, tailscale_listener* listener_out) {
	return TsnetListen(sd, (char*)network, (char*)addr, (int*)listener_out);
}

int tailscale_accept(tailscale_listener ld, tailscale_conn* conn_out) {
	return TsnetAccept(ld, (int*)conn_out);
}

int tailscale_listen_packet(tailscale sd, const char* network, const char* addr, tailscale_listener* listener_out) {
	return TsnetListenPacket(sd, (char*)network, (char*)addr, (int*)listener_out);
}

int tailscale_listen_packet_close(tailscale_listener fd) {
	return TsnetListenPacketClose(fd);
}

int tailscale_getremoteaddr(tailscale_listener l, tailscale_conn conn, char* buf, size_t buflen) {
	return TsnetGetRemoteAddr(l, conn, buf, buflen);
}

int tailscale_getips(tailscale sd, char* buf, size_t buflen) {
	return TsnetGetIps(sd, buf, buflen);
}

int tailscale_set_dir(tailscale sd, const char* dir) {
	return TsnetSetDir(sd, (char*)dir);
}
int tailscale_set_hostname(tailscale sd, const char* hostname) {
	return TsnetSetHostname(sd, (char*)hostname);
}
int tailscale_set_authkey(tailscale sd, const char* authkey) {
	return TsnetSetAuthKey(sd, (char*)authkey);
}
int tailscale_set_control_url(tailscale sd, const char* control_url) {
	return TsnetSetControlURL(sd, (char*)control_url);
}
int tailscale_set_ephemeral(tailscale sd, int ephemeral) {
	return TsnetSetEphemeral(sd, ephemeral);
}
int tailscale_set_logfd(tailscale sd, int fd) {
	return TsnetSetLogFD(sd, fd);
}

int tailscale_loopback(tailscale sd, char* addr_out, size_t addrlen, char* proxy_cred_out, char* local_api_cred_out) {
	return TsnetLoopback(sd, addr_out, addrlen, proxy_cred_out, local_api_cred_out);
}

int tailscale_errmsg(tailscale sd, char* buf, size_t buflen) {
	return TsnetErrmsg(sd, buf, buflen);
}

int tailscale_enable_funnel_to_localhost_plaintext_http1(tailscale sd, int localhostPort) {
	return TsnetEnableFunnelToLocalhostPlaintextHttp1(sd, localhostPort);
}

guest_server guest_server_new() {
	return GuestServerNew();
}
int guest_server_set_derpmap_url(guest_server gd, const char* url) {
	return GuestServerSetDERPMapURL(gd, (char*)url);
}
int guest_server_set_derpmap_json(guest_server gd, const char* dm_json) {
	return GuestServerSetDERPMapJSON(gd, (char*)dm_json);
}
int guest_server_start(guest_server gd) {
	return GuestServerStart(gd);
}
int guest_server_token(guest_server gd, char* buf, size_t buflen) {
	return GuestServerToken(gd, buf, buflen);
}
int guest_server_listen_packet(guest_server gd, unsigned short port, tailscale_listener* fd_out) {
	return GuestServerListenPacket(gd, port, fd_out);
}
int guest_server_listen(guest_server gd, unsigned short port, tailscale_listener* listener_out) {
	return GuestServerListen(gd, port, listener_out);
}
int guest_server_peers(guest_server gd, char* buf, size_t buflen) {
	return GuestServerPeers(gd, buf, buflen);
}
int guest_server_remove_peer(guest_server gd, const char* node_key) {
	return GuestServerRemovePeer(gd, (char*)node_key);
}
int guest_server_errmsg(guest_server gd, char* buf, size_t buflen) {
	return GuestServerErrmsg(gd, buf, buflen);
}
int guest_server_close(guest_server gd) {
	return GuestServerClose(gd);
}
guest_client guest_client_new(const char* token) {
	return GuestClientNew((char*)token);
}
int guest_client_dial(guest_client cd, unsigned short port, tailscale_conn* conn_out) {
	return GuestClientDial(cd, port, conn_out);
}
int guest_client_dial_udp(guest_client cd, unsigned short port, tailscale_listener* fd_out) {
	return GuestClientDialUDP(cd, port, fd_out);
}
int guest_client_server_addr(guest_client cd, char* buf, size_t buflen) {
	return GuestClientServerAddr(cd, buf, buflen);
}
int guest_client_errmsg(guest_client cd, char* buf, size_t buflen) {
	return GuestClientErrmsg(cd, buf, buflen);
}
int guest_client_close(guest_client cd) {
	return GuestClientClose(cd);
}
