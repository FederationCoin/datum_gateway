/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024-2026 Bitcoin Ocean, LLC & Jason Hughes
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "datum_conf.h"
#include "datum_gateway.h"
#include "datum_logger.h"
#include "datum_sockets.h"
#include "datum_stratum.h"
#include "datum_stratum_ws.h"
#include "datum_utils.h"

#define DATUM_WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define DATUM_WS_OP_TEXT 1
#define DATUM_WS_OP_BIN 2
#define DATUM_WS_OP_CLOSE 8
#define DATUM_WS_OP_PING 9
#define DATUM_WS_OP_PONG 10

static uint32_t sha1_rotl(uint32_t v, int n)
{
	return (v << n) | (v >> (32 - n));
}

static void sha1_block(uint32_t h[5], const uint8_t blk[64])
{
	uint32_t w[80];
	uint32_t a, b, c, d, e, f, k, t;
	int i;
	for (i = 0; i < 16; ++i) {
		w[i] = ((uint32_t)blk[4 * i] << 24) | ((uint32_t)blk[4 * i + 1] << 16) | ((uint32_t)blk[4 * i + 2] << 8) | (uint32_t)blk[4 * i + 3];
	}
	for (i = 16; i < 80; ++i) {
		w[i] = sha1_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}
	a = h[0];
	b = h[1];
	c = h[2];
	d = h[3];
	e = h[4];
	for (i = 0; i < 80; ++i) {
		if (i < 20) {
			f = (b & c) | ((~b) & d);
			k = 0x5A827999u;
		} else if (i < 40) {
			f = b ^ c ^ d;
			k = 0x6ED9EBA1u;
		} else if (i < 60) {
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDCu;
		} else {
			f = b ^ c ^ d;
			k = 0xCA62C1D6u;
		}
		t = sha1_rotl(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = sha1_rotl(b, 30);
		b = a;
		a = t;
	}
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
}

static void sha1(const uint8_t *msg, size_t n, uint8_t out[20])
{
	uint32_t h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };
	uint8_t blk[64];
	uint64_t bits = (uint64_t)n * 8;
	size_t i;
	while (n >= 64) {
		sha1_block(h, msg);
		msg += 64;
		n -= 64;
	}
	memset(blk, 0, 64);
	if (n) {
		memcpy(blk, msg, n);
	}
	blk[n] = 0x80;
	if (n >= 56) {
		sha1_block(h, blk);
		memset(blk, 0, 64);
	}
	blk[56] = (uint8_t)(bits >> 56);
	blk[57] = (uint8_t)(bits >> 48);
	blk[58] = (uint8_t)(bits >> 40);
	blk[59] = (uint8_t)(bits >> 32);
	blk[60] = (uint8_t)(bits >> 24);
	blk[61] = (uint8_t)(bits >> 16);
	blk[62] = (uint8_t)(bits >> 8);
	blk[63] = (uint8_t)bits;
	sha1_block(h, blk);
	for (i = 0; i < 5; ++i) {
		out[4 * i] = (uint8_t)(h[i] >> 24);
		out[4 * i + 1] = (uint8_t)(h[i] >> 16);
		out[4 * i + 2] = (uint8_t)(h[i] >> 8);
		out[4 * i + 3] = (uint8_t)h[i];
	}
}

static void b64_20(const uint8_t in[20], char out[29])
{
	static const char *t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	int i, j = 0;
	uint8_t buf[21];
	memcpy(buf, in, 20);
	buf[20] = 0;
	for (i = 0; i < 21; i += 3) {
		uint32_t v = ((uint32_t)buf[i] << 16) | ((uint32_t)buf[i + 1] << 8) | (uint32_t)buf[i + 2];
		out[j++] = t[(v >> 18) & 63];
		out[j++] = t[(v >> 12) & 63];
		out[j++] = t[(v >> 6) & 63];
		out[j++] = t[v & 63];
	}
	out[27] = '=';
	out[28] = 0;
}

void datum_ws_sec_accept(const char *key, char out_b64[DATUM_WS_ACCEPT_B64_LEN + 1])
{
	char concat[128];
	uint8_t digest[20];
	int n;
	n = snprintf(concat, sizeof(concat), "%s%s", key ? key : "", DATUM_WS_GUID);
	if (n < 0 || (size_t)n >= sizeof(concat)) {
		out_b64[0] = 0;
		return;
	}
	sha1((const uint8_t *)concat, (size_t)n, digest);
	b64_20(digest, out_b64);
}

static int ws_encode(uint8_t opcode, const uint8_t *payload, size_t n, int masked, const uint8_t mask[4], uint8_t *out, size_t out_max)
{
	size_t hdr;
	size_t i;
	if (n > DATUM_WS_MAX_PAYLOAD) {
		return -1;
	}
	hdr = 2;
	if (n >= 126) {
		hdr += 2;
	}
	if (masked) {
		hdr += 4;
	}
	if (hdr + n > out_max) {
		return -1;
	}
	out[0] = (uint8_t)(0x80u | (opcode & 0x0fu));
	if (n < 126) {
		out[1] = (uint8_t)n | (masked ? 0x80u : 0);
		if (masked) {
			memcpy(out + 2, mask, 4);
			for (i = 0; i < n; ++i) {
				out[6 + i] = (uint8_t)(payload[i] ^ mask[i & 3]);
			}
		} else {
			memcpy(out + 2, payload, n);
		}
		return (int)(hdr + n);
	}
	out[1] = 126 | (masked ? 0x80u : 0);
	out[2] = (uint8_t)(n >> 8);
	out[3] = (uint8_t)n;
	if (masked) {
		memcpy(out + 4, mask, 4);
		for (i = 0; i < n; ++i) {
			out[8 + i] = (uint8_t)(payload[i] ^ mask[i & 3]);
		}
	} else {
		memcpy(out + 4, payload, n);
	}
	return (int)(hdr + n);
}

int datum_ws_encode_text(const char *payload, size_t n, uint8_t *out, size_t out_max)
{
	return ws_encode(DATUM_WS_OP_TEXT, (const uint8_t *)payload, n, 0, NULL, out, out_max);
}

int datum_ws_encode_masked_text(const char *payload, size_t n, const uint8_t mask[4], uint8_t *out, size_t out_max)
{
	return ws_encode(DATUM_WS_OP_TEXT, (const uint8_t *)payload, n, 1, mask, out, out_max);
}

int datum_ws_encode_close(uint8_t *out, size_t out_max)
{
	return ws_encode(DATUM_WS_OP_CLOSE, NULL, 0, 0, NULL, out, out_max);
}

int datum_ws_encode_pong(const uint8_t *payload, size_t n, uint8_t *out, size_t out_max)
{
	return ws_encode(DATUM_WS_OP_PONG, payload, n, 0, NULL, out, out_max);
}

int datum_ws_decode_frame(const uint8_t *in, size_t in_len, int *opcode, uint8_t *payload, size_t payload_max, size_t *payload_len, size_t *consumed)
{
	size_t hdr;
	size_t n;
	int masked;
	const uint8_t *mask;
	size_t i;
	if (in_len < 2) {
		return 0;
	}
	if ((in[0] & 0x80) == 0) {
		return -1;
	}
	*opcode = in[0] & 0x0f;
	masked = (in[1] & 0x80) ? 1 : 0;
	n = (size_t)(in[1] & 0x7f);
	hdr = 2;
	if (n == 126) {
		if (in_len < 4) {
			return 0;
		}
		n = ((size_t)in[2] << 8) | (size_t)in[3];
		hdr = 4;
	} else if (n == 127) {
		return -1;
	}
	if (n > DATUM_WS_MAX_PAYLOAD) {
		return -1;
	}
	if (masked) {
		if (in_len < hdr + 4) {
			return 0;
		}
		mask = in + hdr;
		hdr += 4;
	} else {
		mask = NULL;
	}
	if (in_len < hdr + n) {
		return 0;
	}
	if (n > payload_max) {
		return -1;
	}
	if (masked) {
		for (i = 0; i < n; ++i) {
			payload[i] = (uint8_t)(in[hdr + i] ^ mask[i & 3]);
		}
	} else {
		memcpy(payload, in + hdr, n);
	}
	*payload_len = n;
	*consumed = hdr + n;
	return 1;
}

static int contains_ci(const char *hay, const char *needle)
{
	size_t n;
	if (!hay || !needle) {
		return 0;
	}
	n = strlen(needle);
	for (; *hay; ++hay) {
		if (strncasecmp(hay, needle, n) == 0) {
			return 1;
		}
	}
	return 0;
}

static int header_line_value(const char *headers, const char *name, char *out, size_t out_sz)
{
	const char *p = headers;
	size_t nlen = strlen(name);
	while (*p) {
		const char *nl = strstr(p, "\r\n");
		size_t linelen = nl ? (size_t)(nl - p) : strlen(p);
		if (linelen >= nlen + 1 && strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
			const char *v = p + nlen + 1;
			while (*v == ' ' || *v == '\t') {
				++v;
			}
			size_t vn = linelen - (size_t)(v - p);
			while (vn && (v[vn - 1] == ' ' || v[vn - 1] == '\t')) {
				--vn;
			}
			if (vn >= out_sz) {
				return -1;
			}
			memcpy(out, v, vn);
			out[vn] = 0;
			return 0;
		}
		if (!nl) {
			break;
		}
		p = nl + 2;
	}
	return -1;
}

static int path_is_stratum(const char *req)
{
	const char *p;
	if (strncmp(req, "GET ", 4) != 0) {
		return 0;
	}
	p = req + 4;
	if (strncmp(p, "/stratum", 8) != 0) {
		return 0;
	}
	p += 8;
	return (*p == ' ' || *p == '?' || *p == '\r');
}

int datum_ws_handshake_server(int fd)
{
	char req[4096];
	char key[128];
	char upgrade[64];
	char connection[128];
	char accept[DATUM_WS_ACCEPT_B64_LEN + 1];
	char resp[512];
	int n = 0;
	int r;
	struct pollfd pfd;
	const char *end;

	memset(req, 0, sizeof(req));
	pfd.fd = fd;
	pfd.events = POLLIN;
	while (n < (int)sizeof(req) - 1) {
		if (poll(&pfd, 1, 3000) <= 0) {
			return -1;
		}
		r = (int)recv(fd, req + n, sizeof(req) - 1 - (size_t)n, 0);
		if (r <= 0) {
			return -1;
		}
		n += r;
		req[n] = 0;
		end = strstr(req, "\r\n\r\n");
		if (end) {
			break;
		}
	}
	if (!strstr(req, "\r\n\r\n")) {
		return -1;
	}
	if (!path_is_stratum(req)) {
		return -1;
	}
	if (header_line_value(req, "Sec-WebSocket-Key", key, sizeof(key)) != 0 || key[0] == 0) {
		return -1;
	}
	if (header_line_value(req, "Upgrade", upgrade, sizeof(upgrade)) != 0 || strcasecmp(upgrade, "websocket") != 0) {
		return -1;
	}
	if (header_line_value(req, "Connection", connection, sizeof(connection)) != 0 || !contains_ci(connection, "Upgrade")) {
		return -1;
	}
	if (contains_ci(req, "\r\nAuthorization:")) {
		return -1;
	}
	datum_ws_sec_accept(key, accept);
	r = snprintf(resp, sizeof(resp),
		"HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Accept: %s\r\n"
		"\r\n",
		accept);
	if (r < 0 || (size_t)r >= sizeof(resp)) {
		return -1;
	}
	if (send(fd, resp, (size_t)r, 0) != r) {
		return -1;
	}
	return 0;
}

static int ws_queue_bytes(T_DATUM_CLIENT_DATA *c, const uint8_t *p, int n)
{
	if (n <= 0) {
		return n;
	}
	if ((c->out_buf + n) >= CLIENT_BUFFER) {
		return -1;
	}
	memcpy(&c->w_buffer[c->out_buf], p, (size_t)n);
	c->out_buf += n;
	return n;
}

int datum_ws_queue_text_line(T_DATUM_CLIENT_DATA *c, const char *line, size_t n)
{
	uint8_t framed[2048];
	int fl;
	fl = datum_ws_encode_text(line, n, framed, sizeof(framed));
	if (fl < 0) {
		return -1;
	}
	return ws_queue_bytes(c, framed, fl);
}

int datum_ws_client_feed(T_DATUM_CLIENT_DATA *c)
{
	uint8_t payload[DATUM_WS_MAX_PAYLOAD + 1];
	size_t payload_len = 0;
	size_t consumed = 0;
	int opcode = 0;
	int rc;
	size_t off = 0;

	while (off < (size_t)c->in_buf) {
		rc = datum_ws_decode_frame((const uint8_t *)c->buffer + off, (size_t)c->in_buf - off, &opcode, payload, DATUM_WS_MAX_PAYLOAD, &payload_len, &consumed);
		if (rc == 0) {
			break;
		}
		if (rc < 0) {
			return -1;
		}
		off += consumed;
		if (opcode == DATUM_WS_OP_BIN) {
			return -1;
		}
		if (opcode == DATUM_WS_OP_CLOSE) {
			return -1;
		}
		if (opcode == DATUM_WS_OP_PING) {
			uint8_t pong[128];
			int pn = datum_ws_encode_pong(payload, payload_len > 125 ? 125 : payload_len, pong, sizeof(pong));
			if (pn < 0 || ws_queue_bytes(c, pong, pn) < 0) {
				return -1;
			}
			continue;
		}
		if (opcode == DATUM_WS_OP_PONG) {
			continue;
		}
		if (opcode != DATUM_WS_OP_TEXT) {
			return -1;
		}
		payload[payload_len] = 0;
		{
			char *start = (char *)payload;
			char *nl;
			if (payload_len && payload[payload_len - 1] != '\n') {
				if (payload_len + 1 > DATUM_WS_MAX_PAYLOAD) {
					return -1;
				}
				payload[payload_len] = '\n';
				payload[payload_len + 1] = 0;
				++payload_len;
			}
			while ((nl = strchr(start, '\n')) != NULL) {
				*nl = 0;
				if (start[0] && c->datum_thread && c->datum_thread->app && c->datum_thread->app->client_cmd_func) {
					if (c->datum_thread->app->client_cmd_func(c, start) < 0) {
						return -1;
					}
				}
				start = nl + 1;
			}
			if (start[0]) {
				return -1;
			}
		}
	}
	if (off > 0) {
		size_t left = (size_t)c->in_buf - off;
		if (left) {
			memmove(c->buffer, c->buffer + off, left);
		}
		c->in_buf = (int)left;
	}
	return 0;
}

void *datum_stratum_ws_server(void *arg)
{
	int listen_socks[2] = { -1, -1 };
	size_t listen_socks_len = 2;
	int epollfd;
	struct epoll_event ev, events[MAX_EVENTS];
	int nfds, i, conn_sock;
	(void)arg;

	if (datum_config.stratum_ws_listen_port <= 0) {
		DLOG_DEBUG("Stratum WebSocket disabled (ws_listen_port=0)");
		return NULL;
	}

	while (!global_stratum_app) {
		usleep(50000);
	}

	DLOG_DEBUG("Setting up Stratum WebSocket on %s port %d path /stratum",
		datum_config.stratum_ws_listen_addr[0] ? datum_config.stratum_ws_listen_addr : "(any)",
		datum_config.stratum_ws_listen_port);

	if (!datum_sockets_setup_listening_sockets("stratum-ws", datum_config.stratum_ws_listen_addr, (uint16_t)datum_config.stratum_ws_listen_port, listen_socks, &listen_socks_len)) {
		DLOG_FATAL("Could not bind Stratum WebSocket listener");
		return NULL;
	}
	if (listen_socks_len < 2) {
		listen_socks[1] = -1;
	}

	epollfd = epoll_create1(0);
	if (epollfd < 0) {
		DLOG_FATAL("epoll_create1 failed: %s", strerror(errno));
		return NULL;
	}
	for (i = 0; i < 2; ++i) {
		if (listen_socks[i] < 0) {
			continue;
		}
		ev.events = EPOLLIN;
		ev.data.fd = listen_socks[i];
		if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ev.data.fd, &ev) < 0) {
			DLOG_FATAL("epoll_ctl failed: %s", strerror(errno));
			return NULL;
		}
	}

	DLOG_INFO("Stratum WebSocket listener active (path /stratum)");
	for (;;) {
		nfds = epoll_wait(epollfd, events, MAX_EVENTS, 200);
		for (i = 0; i < nfds; ++i) {
			if (events[i].data.fd != listen_socks[0] && events[i].data.fd != listen_socks[1]) {
				continue;
			}
			conn_sock = accept(events[i].data.fd, NULL, NULL);
			if (conn_sock < 0) {
				continue;
			}
			if (datum_ws_handshake_server(conn_sock) != 0) {
				close(conn_sock);
				continue;
			}
			datum_socket_setoptions(conn_sock);
			if (!assign_to_thread(global_stratum_app, conn_sock, true)) {
				close(conn_sock);
			}
		}
	}
	return NULL;
}
