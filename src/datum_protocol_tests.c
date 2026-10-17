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

#include <string.h>

#include "datum_protocol.h"
#include "datum_utils.h"

static void xor_initial_header(T_DATUM_PROTOCOL_HEADER *h)
{
	uint32_t v;
	memcpy(&v, h, sizeof(v));
	v ^= DATUM_PROTOCOL_INITIAL_HEADER_XOR;
	memcpy(h, &v, sizeof(v));
}

static T_DATUM_PROTOCOL_HEADER identity_wire(void)
{
	T_DATUM_PROTOCOL_HEADER h;
	memset(&h, 0, sizeof(h));
	h.cmd_len = DATUM_PROTOCOL_IDENTITY_SIZE;
	h.proto_cmd = DATUM_PROTOCOL_IDENTITY_CMD;
	xor_initial_header(&h);
	return h;
}

void datum_protocol_tests(void)
{
	T_DATUM_PROTOCOL_HEADER h;
	T_DATUM_PROTOCOL_HEADER orig;

	h = identity_wire();
	datum_test(datum_protocol_decode_identity_header(&h));
	datum_test(h.proto_cmd == DATUM_PROTOCOL_IDENTITY_CMD);
	datum_test(h.cmd_len == DATUM_PROTOCOL_IDENTITY_SIZE);
	datum_test(!h.is_signed);
	datum_test(!h.is_encrypted_pubkey);
	datum_test(!h.is_encrypted_channel);

	memset(&h, 0, sizeof(h));
	orig = h;
	datum_test(!datum_protocol_decode_identity_header(&h));
	datum_test(memcmp(&h, &orig, sizeof(h)) == 0);

	memset(&h, 0, sizeof(h));
	h.cmd_len = DATUM_PROTOCOL_IDENTITY_SIZE;
	h.proto_cmd = DATUM_PROTOCOL_IDENTITY_CMD;
	orig = h;
	datum_test(!datum_protocol_decode_identity_header(&h));
	datum_test(memcmp(&h, &orig, sizeof(h)) == 0);

	memset(&h, 0, sizeof(h));
	h.cmd_len = DATUM_PROTOCOL_IDENTITY_SIZE;
	h.proto_cmd = DATUM_PROTOCOL_IDENTITY_CMD;
	h.is_signed = true;
	xor_initial_header(&h);
	orig = h;
	datum_test(!datum_protocol_decode_identity_header(&h));
	datum_test(memcmp(&h, &orig, sizeof(h)) == 0);

	memset(&h, 0, sizeof(h));
	h.cmd_len = DATUM_PROTOCOL_IDENTITY_SIZE;
	h.proto_cmd = DATUM_PROTOCOL_IDENTITY_CMD;
	h.is_encrypted_pubkey = true;
	xor_initial_header(&h);
	orig = h;
	datum_test(!datum_protocol_decode_identity_header(&h));
	datum_test(memcmp(&h, &orig, sizeof(h)) == 0);

	memset(&h, 0, sizeof(h));
	h.cmd_len = DATUM_PROTOCOL_IDENTITY_SIZE;
	h.proto_cmd = DATUM_PROTOCOL_IDENTITY_CMD;
	h.is_encrypted_channel = true;
	xor_initial_header(&h);
	orig = h;
	datum_test(!datum_protocol_decode_identity_header(&h));
	datum_test(memcmp(&h, &orig, sizeof(h)) == 0);

	memset(&h, 0, sizeof(h));
	h.cmd_len = DATUM_PROTOCOL_IDENTITY_SIZE;
	h.proto_cmd = DATUM_PROTOCOL_IDENTITY_CMD;
	h.reserved = 1;
	xor_initial_header(&h);
	orig = h;
	datum_test(!datum_protocol_decode_identity_header(&h));
	datum_test(memcmp(&h, &orig, sizeof(h)) == 0);

	memset(&h, 0, sizeof(h));
	h.cmd_len = 32;
	h.proto_cmd = DATUM_PROTOCOL_IDENTITY_CMD;
	xor_initial_header(&h);
	orig = h;
	datum_test(!datum_protocol_decode_identity_header(&h));
	datum_test(memcmp(&h, &orig, sizeof(h)) == 0);

	memset(&h, 0, sizeof(h));
	h.cmd_len = 200;
	h.proto_cmd = 2;
	h.is_signed = true;
	h.is_encrypted_pubkey = true;
	xor_initial_header(&h);
	orig = h;
	datum_test(!datum_protocol_decode_identity_header(&h));
	datum_test(memcmp(&h, &orig, sizeof(h)) == 0);

	datum_test(!datum_protocol_decode_identity_header(NULL));
}
