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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <jansson.h>

#include "datum_conf.h"
#include "datum_stratum_ws.h"
#include "datum_utils.h"

static const uint8_t k_mask[4] = { 0x37, 0xfa, 0x21, 0x3d };

static int send_all(int fd, const void *p, size_t n)
{
	const uint8_t *b = p;
	while (n) {
		ssize_t w = send(fd, b, n, 0);
		if (w <= 0) {
			return -1;
		}
		b += (size_t)w;
		n -= (size_t)w;
	}
	return 0;
}

static int client_handshake(int fd)
{
	char resp[1024];
	int n = 0;
	struct pollfd pfd;
	const char *req =
		"GET /stratum HTTP/1.1\r\n"
		"Host: 127.0.0.1\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"\r\n";
	if (send_all(fd, req, strlen(req)) != 0) {
		return -1;
	}
	memset(resp, 0, sizeof(resp));
	pfd.fd = fd;
	pfd.events = POLLIN;
	while (n < (int)sizeof(resp) - 1) {
		if (poll(&pfd, 1, 3000) <= 0) {
			return -1;
		}
		ssize_t r = recv(fd, resp + n, sizeof(resp) - 1 - (size_t)n, 0);
		if (r <= 0) {
			return -1;
		}
		n += (int)r;
		resp[n] = 0;
		if (strstr(resp, "\r\n\r\n")) {
			break;
		}
	}
	return (strstr(resp, "101") && strstr(resp, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")) ? 0 : -1;
}

static int send_text(int fd, const char *s)
{
	uint8_t framed[2048];
	int n = datum_ws_encode_masked_text(s, strlen(s), k_mask, framed, sizeof(framed));
	if (n < 0) {
		return -1;
	}
	return send_all(fd, framed, (size_t)n);
}

static int recv_text(int fd, char *out, size_t out_sz)
{
	uint8_t payload[DATUM_WS_MAX_PAYLOAD];
	size_t plen = 0;
	size_t consumed = 0;
	uint8_t buf[2048];
	size_t have = 0;
	int opcode = 0;
	struct pollfd pfd;
	pfd.fd = fd;
	pfd.events = POLLIN;
	for (;;) {
		int rc = 0;
		if (have) {
			rc = datum_ws_decode_frame(buf, have, &opcode, payload, sizeof(payload), &plen, &consumed);
			if (rc == 1) {
				if (opcode != 1 || plen >= out_sz) {
					return -1;
				}
				memcpy(out, payload, plen);
				out[plen] = 0;
				return 0;
			}
			if (rc < 0) {
				return -1;
			}
		}
		if (poll(&pfd, 1, 3000) <= 0) {
			return -1;
		}
		if (have >= sizeof(buf)) {
			return -1;
		}
		{
			ssize_t r = recv(fd, buf + have, sizeof(buf) - have, 0);
			if (r <= 0) {
				return -1;
			}
			have += (size_t)r;
		}
	}
}

struct ws_test_srv {
	int listen_fd;
	uint16_t port;
	volatile int ready;
	volatile int fail;
};

static void *ws_rpc_thread(void *arg)
{
	struct ws_test_srv *s = arg;
	int cfd;
	char line[2048];
	int opcode;
	uint8_t payload[DATUM_WS_MAX_PAYLOAD];
	size_t plen = 0, consumed = 0;
	uint8_t in[4096];
	size_t have = 0;
	const char *coinb1 =
		"000000111111111111111111111111111111111111111111111111111111111111111100000000";
	const char *notify;
	char notify_buf[512];
	struct pollfd pfd;

	cfd = accept(s->listen_fd, NULL, NULL);
	if (cfd < 0) {
		s->fail = 1;
		return NULL;
	}
	if (datum_ws_handshake_server(cfd) != 0) {
		close(cfd);
		s->fail = 1;
		return NULL;
	}

	pfd.fd = cfd;
	pfd.events = POLLIN;
	while (have < sizeof(in)) {
		if (poll(&pfd, 1, 3000) <= 0) {
			s->fail = 1;
			close(cfd);
			return NULL;
		}
		ssize_t r = recv(cfd, in + have, sizeof(in) - have, 0);
		if (r <= 0) {
			s->fail = 1;
			close(cfd);
			return NULL;
		}
		have += (size_t)r;
		if (datum_ws_decode_frame(in, have, &opcode, payload, sizeof(payload), &plen, &consumed) == 1) {
			payload[plen] = 0;
			if (opcode != 1 || !strstr((char *)payload, "mining.subscribe")) {
				s->fail = 1;
				close(cfd);
				return NULL;
			}
			break;
		}
	}
	send_text(cfd, "{\"error\":null,\"id\":1,\"result\":[[[\"mining.notify\",\"aabbccdd1\"],[\"mining.set_difficulty\",\"aabbccdd2\"]],\"aabbccdd\",8]}\n");
	usleep(50000);

	have = 0;
	while (have < sizeof(in)) {
		if (poll(&pfd, 1, 3000) <= 0) {
			s->fail = 1;
			close(cfd);
			return NULL;
		}
		ssize_t r = recv(cfd, in + have, sizeof(in) - have, 0);
		if (r <= 0) {
			s->fail = 1;
			close(cfd);
			return NULL;
		}
		have += (size_t)r;
		if (datum_ws_decode_frame(in, have, &opcode, payload, sizeof(payload), &plen, &consumed) == 1) {
			payload[plen] = 0;
			if (opcode != 1 || !strstr((char *)payload, "mining.authorize") || !strstr((char *)payload, "\"x\"")) {
				s->fail = 1;
				close(cfd);
				return NULL;
			}
			break;
		}
	}
	send_text(cfd, "{\"error\":null,\"id\":2,\"result\":true}\n");
	usleep(150000);

	snprintf(notify_buf, sizeof(notify_buf),
		"{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"job00\",\"%s\",\"%s\",\"\",[],\"80000001\",\"1d00ffff\",\"00000000e8030000\",true]}\n",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		coinb1);
	notify = notify_buf;
	send_text(cfd, notify);

	have = 0;
	while (have < sizeof(in)) {
		if (poll(&pfd, 1, 3000) <= 0) {
			s->fail = 1;
			close(cfd);
			return NULL;
		}
		ssize_t r = recv(cfd, in + have, sizeof(in) - have, 0);
		if (r <= 0) {
			s->fail = 1;
			close(cfd);
			return NULL;
		}
		have += (size_t)r;
		if (datum_ws_decode_frame(in, have, &opcode, payload, sizeof(payload), &plen, &consumed) == 1) {
			payload[plen] = 0;
			if (opcode != 1 || !strstr((char *)payload, "mining.submit")) {
				s->fail = 1;
				close(cfd);
				return NULL;
			}
			break;
		}
	}
	send_text(cfd, "{\"error\":null,\"id\":3,\"result\":true}\n");

	/* next connection path is junk-frame close on this socket: wait for binary */
	have = 0;
	while (have < sizeof(in)) {
		if (poll(&pfd, 1, 3000) <= 0) {
			break;
		}
		ssize_t r = recv(cfd, in + have, sizeof(in) - have, 0);
		if (r <= 0) {
			break;
		}
		have += (size_t)r;
		if (datum_ws_decode_frame(in, have, &opcode, payload, sizeof(payload), &plen, &consumed) < 0 || opcode == 2) {
			uint8_t cl[16];
			int cn = datum_ws_encode_close(cl, sizeof(cl));
			if (cn > 0) {
				send_all(cfd, cl, (size_t)cn);
			}
			break;
		}
	}
	close(cfd);
	(void)line;
	return NULL;
}

static void datum_stratum_ws_accept_key_test(void)
{
	char out[DATUM_WS_ACCEPT_B64_LEN + 1];
	datum_ws_sec_accept("dGhlIHNhbXBsZSBub25jZQ==", out);
	datum_test(strcmp(out, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") == 0);
}

static void datum_stratum_ws_port0_test(void)
{
	datum_config.stratum_ws_listen_port = 0;
	datum_test(datum_stratum_ws_server(NULL) == NULL);
}

static void datum_stratum_ws_rpc_test(void)
{
	struct ws_test_srv s;
	pthread_t th;
	int cfd;
	struct sockaddr_in addr;
	socklen_t alen = sizeof(addr);
	char msg[2048];
	json_error_t err;
	json_t *j;
	const char *coinb1;
	uint8_t bin[8];

	memset(&s, 0, sizeof(s));
	s.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	datum_test(s.listen_fd >= 0);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	datum_test(bind(s.listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	datum_test(listen(s.listen_fd, 1) == 0);
	datum_test(getsockname(s.listen_fd, (struct sockaddr *)&addr, &alen) == 0);
	s.port = ntohs(addr.sin_port);

	datum_test(pthread_create(&th, NULL, ws_rpc_thread, &s) == 0);

	cfd = socket(AF_INET, SOCK_STREAM, 0);
	datum_test(cfd >= 0);
	datum_test(connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
	datum_test(client_handshake(cfd) == 0);

	datum_test(send_text(cfd, "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"test\"]}\n") == 0);
	datum_test(recv_text(cfd, msg, sizeof(msg)) == 0);
	j = json_loads(msg, 0, &err);
	datum_test(j != NULL);
	if (j) {
		json_t *result = json_object_get(j, "result");
		datum_test(json_is_array(result) && json_array_size(result) >= 3);
		datum_test(json_integer_value(json_array_get(result, 2)) == 8);
		json_decref(j);
	}

	datum_test(send_text(cfd, "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"worker\",\"x\"]}\n") == 0);
	datum_test(recv_text(cfd, msg, sizeof(msg)) == 0);
	j = json_loads(msg, 0, &err);
	datum_test(j != NULL);
	if (j) {
		datum_test(json_is_true(json_object_get(j, "result")));
		json_decref(j);
	}

	datum_test(recv_text(cfd, msg, sizeof(msg)) == 0);
	j = json_loads(msg, 0, &err);
	datum_test(j != NULL);
	if (j) {
		json_t *params = json_object_get(j, "params");
		datum_test(json_string_value(json_object_get(j, "method")) && strcmp(json_string_value(json_object_get(j, "method")), "mining.notify") == 0);
		datum_test(json_is_array(params) && json_array_size(params) >= 9);
		coinb1 = json_string_value(json_array_get(params, 2));
		datum_test(coinb1 && strlen(coinb1) == 78);
		datum_test(json_string_value(json_array_get(params, 3)) && json_string_value(json_array_get(params, 3))[0] == 0);
		datum_test(json_is_array(json_array_get(params, 4)) && json_array_size(json_array_get(params, 4)) == 0);
		json_decref(j);
	}

	datum_test(send_text(cfd, "{\"id\":3,\"method\":\"mining.submit\",\"params\":[\"worker\",\"job00\",\"0000000000000000\",\"00000000e8030000\",\"0100000000000000\"]}\n") == 0);
	datum_test(recv_text(cfd, msg, sizeof(msg)) == 0);
	j = json_loads(msg, 0, &err);
	datum_test(j != NULL);
	if (j) {
		datum_test(json_is_true(json_object_get(j, "result")));
		json_decref(j);
	}

	bin[0] = 0x82;
	bin[1] = 0x80 | 1;
	bin[2] = k_mask[0];
	bin[3] = k_mask[1];
	bin[4] = k_mask[2];
	bin[5] = k_mask[3];
	bin[6] = (uint8_t)('x' ^ k_mask[0]);
	datum_test(send_all(cfd, bin, 7) == 0);
	close(cfd);
	pthread_join(th, NULL);
	close(s.listen_fd);
	datum_test(s.fail == 0);
}

static void datum_stratum_ws_pool_info_tests(void)
{
	char buf[2048];
	json_error_t err;
	json_t *j;
	json_t *result;
	int i;

	datum_config.stratum_ws_pool_info = true;
	memset(datum_config.datum_pool_host, 0, sizeof(datum_config.datum_pool_host));
	strcpy(datum_config.datum_pool_host, "prime.example");
	datum_config.datum_pool_port = 28916;
	memset(datum_config.mining_pool_name, 0, sizeof(datum_config.mining_pool_name));
	strcpy(datum_config.mining_pool_name, "House");
	memset(datum_config.mining_coinbase_tag_primary, 0, sizeof(datum_config.mining_coinbase_tag_primary));
	strcpy(datum_config.mining_coinbase_tag_primary, "TAG");
	memset(datum_config.mining_pool_website, 0, sizeof(datum_config.mining_pool_website));
	strcpy(datum_config.mining_pool_website, "https://ex.example");

	datum_test(datum_ws_format_pool_info_result(9, buf, sizeof(buf)) == 0);
	j = json_loads(buf, 0, &err);
	datum_test(j != NULL);
	if (j) {
		datum_test(json_integer_value(json_object_get(j, "id")) == 9);
		datum_test(json_is_null(json_object_get(j, "error")));
		result = json_object_get(j, "result");
		datum_test(json_is_object(result));
		datum_test(strcmp(json_string_value(json_object_get(result, "prime")), "prime.example:28916") == 0);
		datum_test(strcmp(json_string_value(json_object_get(result, "name")), "House") == 0);
		datum_test(strcmp(json_string_value(json_object_get(result, "coinbaseTag")), "TAG") == 0);
		datum_test(strcmp(json_string_value(json_object_get(result, "websiteUrl")), "https://ex.example") == 0);
		json_decref(j);
	}

	datum_config.datum_pool_host[0] = 0;
	datum_test(datum_ws_format_pool_info_object(buf, sizeof(buf)) == 0);
	j = json_loads(buf, 0, &err);
	datum_test(j != NULL);
	if (j) {
		datum_test(json_string_value(json_object_get(j, "prime")) && json_string_value(json_object_get(j, "prime"))[0] == 0);
		json_decref(j);
	}

	datum_test(datum_ws_format_pool_info_error(9, 24, "pool info disabled", buf, sizeof(buf)) == 0);
	j = json_loads(buf, 0, &err);
	datum_test(j != NULL);
	if (j) {
		json_t *e = json_object_get(j, "error");
		datum_test(json_is_array(e) && json_integer_value(json_array_get(e, 0)) == 24);
		datum_test(strcmp(json_string_value(json_array_get(e, 1)), "pool info disabled") == 0);
		json_decref(j);
	}

	datum_test(datum_ws_format_pool_info_notify(buf, sizeof(buf)) == 0);
	j = json_loads(buf, 0, &err);
	datum_test(j != NULL);
	if (j) {
		datum_test(json_is_null(json_object_get(j, "id")));
		datum_test(strcmp(json_string_value(json_object_get(j, "method")), "client.pool_info") == 0);
		json_decref(j);
	}

	datum_test(datum_ws_pool_info_rate_ok(0, 1000));
	datum_test(!datum_ws_pool_info_rate_ok(1000, 5999));
	datum_test(datum_ws_pool_info_rate_ok(1000, 6000));

	datum_test(strstr(datum_ws_http_429(), "429") != NULL);

	datum_ws_ip_reset();
	for (i = 0; i < DATUM_WS_MAX_PER_IP; i++) {
		datum_test(datum_ws_ip_acquire("127.0.0.1") == 1);
	}
	datum_test(datum_ws_ip_acquire("127.0.0.1") == 0);
	datum_ws_ip_release("127.0.0.1");
	datum_test(datum_ws_ip_acquire("127.0.0.1") == 1);
	datum_test(datum_ws_ip_acquire("10.0.0.2") == 1);
	datum_ws_ip_reset();
}

void datum_stratum_ws_tests(void)
{
	datum_stratum_ws_accept_key_test();
	datum_stratum_ws_port0_test();
	datum_stratum_ws_rpc_test();
	datum_stratum_ws_pool_info_tests();
}
