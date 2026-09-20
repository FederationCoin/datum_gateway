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

#ifndef _DATUM_STRATUM_WS_H_
#define _DATUM_STRATUM_WS_H_

#include <stddef.h>
#include <stdint.h>

#include "datum_gateway.h"
#include "datum_sockets.h"

#define DATUM_WS_MAX_PAYLOAD 16384
#define DATUM_WS_ACCEPT_B64_LEN 28

int datum_ws_encode_text(const char *payload, size_t n, uint8_t *out, size_t out_max);
int datum_ws_encode_masked_text(const char *payload, size_t n, const uint8_t mask[4], uint8_t *out, size_t out_max);
int datum_ws_encode_close(uint8_t *out, size_t out_max);
int datum_ws_encode_pong(const uint8_t *payload, size_t n, uint8_t *out, size_t out_max);

/* 1 = frame, 0 = need more, -1 = close (binary/oversize/junk). */
int datum_ws_decode_frame(const uint8_t *in, size_t in_len, int *opcode, uint8_t *payload, size_t payload_max, size_t *payload_len, size_t *consumed);

void datum_ws_sec_accept(const char *key, char out_b64[DATUM_WS_ACCEPT_B64_LEN + 1]);
int datum_ws_handshake_server(int fd);
int datum_ws_queue_text_line(T_DATUM_CLIENT_DATA *c, const char *line, size_t n);
int datum_ws_client_feed(T_DATUM_CLIENT_DATA *c);

void *datum_stratum_ws_server(void *arg);
void datum_stratum_ws_tests(void);

#endif
