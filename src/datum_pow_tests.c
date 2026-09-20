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

#include <stdio.h>
#include <string.h>

#include <jansson.h>

#include "datum_pow.h"
#include "datum_utils.h"

static const char *vector_paths[] = {
#ifdef DATUM_BLOCK_HEADER_V2_JSON
	DATUM_BLOCK_HEADER_V2_JSON,
#endif
	"src/test/block_header_v2.json",
	"../src/test/block_header_v2.json",
	"../../src/test/block_header_v2.json",
	NULL
};

static json_t *load_vectors(void)
{
	json_error_t err;
	const char **p;
	for (p = vector_paths; *p; ++p) {
		json_t *root = json_load_file(*p, 0, &err);
		if (root) {
			return root;
		}
	}
	fprintf(stderr, "ERROR: could not load block_header_v2.json\n");
	return NULL;
}

static bool header_from_fields(json_t *fields, datum_header_v2_t *h)
{
	json_t *v;
	memset(h, 0, sizeof(*h));
	v = json_object_get(fields, "nVersion");
	if (!json_is_integer(v)) {
		return false;
	}
	h->nVersion = (int32_t)json_integer_value(v);
	if (!datum_pow_u256_from_hex(json_string_value(json_object_get(fields, "hashPrevBlock")), h->hashPrevBlock)) {
		return false;
	}
	if (!datum_pow_u256_from_hex(json_string_value(json_object_get(fields, "hashMerkleRoot")), h->hashMerkleRoot)) {
		return false;
	}
	h->nTime = (uint32_t)json_integer_value(json_object_get(fields, "nTime"));
	h->nBits = (uint32_t)json_integer_value(json_object_get(fields, "nBits"));
	h->nNonce = (uint32_t)json_integer_value(json_object_get(fields, "nNonce"));
	h->nonce2 = (uint32_t)json_integer_value(json_object_get(fields, "m_nonce2"));
	h->nonce3 = (uint32_t)json_integer_value(json_object_get(fields, "m_nonce3"));
	if (!datum_pow_u128_from_hex_reversed(json_string_value(json_object_get(fields, "m_extranonce")), h->extranonce)) {
		return false;
	}
	h->time_offset = (uint32_t)json_integer_value(json_object_get(fields, "m_time_offset"));
	h->txcount = (uint16_t)json_integer_value(json_object_get(fields, "m_txcount"));
	h->flags = (uint8_t)json_integer_value(json_object_get(fields, "m_flags"));
	h->xor_key_mask_clear_bits = (uint8_t)json_integer_value(json_object_get(fields, "m_xor_key_mask_clear_bits"));
	if (!datum_pow_u128_from_hex_reversed(json_string_value(json_object_get(fields, "m_xor_key")), h->xor_key)) {
		return false;
	}
	h->height = (int32_t)json_integer_value(json_object_get(fields, "m_height"));
	if (!datum_pow_u256_from_hex(json_string_value(json_object_get(fields, "m_mm_rhs")), h->mm_rhs)) {
		return false;
	}
	return true;
}

static void datum_pow_vector_tests(void)
{
	json_t *root = load_vectors();
	json_t *headers;
	size_t i;
	int n = 0;
	if (!datum_test(root != NULL)) {
		return;
	}
	headers = json_object_get(root, "headers");
	if (!datum_test(json_is_array(headers))) {
		json_decref(root);
		return;
	}
	for (i = 0; i < json_array_size(headers); ++i) {
		json_t *row = json_array_get(headers, i);
		json_t *fields = json_object_get(row, "fields");
		const char *name = json_string_value(json_object_get(row, "name"));
		const char *want_ser = json_string_value(json_object_get(row, "serialized"));
		const char *want_hash = json_string_value(json_object_get(row, "block_hash"));
		const char *want_asic = json_string_value(json_object_get(row, "asic_input"));
		datum_header_v2_t h;
		datum_header_v2_t decoded;
		uint8_t ser[DATUM_HEADER_V2_SIZE];
		uint8_t asic[256];
		char got_ser[DATUM_HEADER_V2_SIZE * 2 + 1];
		char got_hash[65];
		char got_asic[513];
		int asic_n;
		if (!name) {
			name = "?";
		}
		if (!datum_test(header_from_fields(fields, &h))) {
			fprintf(stderr, "bad fields for %s\n", name);
			continue;
		}
		datum_pow_serialize_header(&h, ser);
		datum_pow_bytes_to_hex(ser, DATUM_HEADER_V2_SIZE, got_ser);
		datum_pow_header_hash_hex(&h, got_hash);
		asic_n = datum_pow_asic_preimage(&h, asic, sizeof(asic));
		if (asic_n > 0) {
			datum_pow_bytes_to_hex(asic, (size_t)asic_n, got_asic);
		} else {
			got_asic[0] = 0;
		}
		if (!datum_test(want_ser && strcmp(got_ser, want_ser) == 0)) {
			fprintf(stderr, "%s serialize mismatch\n got  %s\n want %s\n", name, got_ser, want_ser ? want_ser : "(null)");
		}
		if (!datum_test(want_hash && strcmp(got_hash, want_hash) == 0)) {
			fprintf(stderr, "%s hash mismatch\n got  %s\n want %s\n", name, got_hash, want_hash ? want_hash : "(null)");
		}
		if (!datum_test(want_asic && strcmp(got_asic, want_asic) == 0)) {
			fprintf(stderr, "%s asic_input mismatch\n got  %s\n want %s\n", name, got_asic, want_asic ? want_asic : "(null)");
		}
		if (!datum_test(datum_pow_deserialize_header(ser, &decoded))) {
			fprintf(stderr, "%s deserialize failed\n", name);
		} else {
			char round[65];
			datum_pow_header_hash_hex(&decoded, round);
			if (!datum_test(want_hash && strcmp(round, want_hash) == 0)) {
				fprintf(stderr, "%s round-trip hash mismatch\n", name);
			}
		}
		++n;
	}
	datum_test(n == 5);
	json_decref(root);
}

static void datum_pow_hasher_work_tests(void)
{
	datum_header_v2_t h;
	uint8_t commitment[32];
	uint8_t coinb1[DATUM_HASHER_COINB1_SIZE];
	uint8_t en12[12];
	uint8_t root[32];
	uint8_t prev_hidden[32];
	uint8_t nonce8[8];
	uint8_t ntime8[8];
	uint8_t work[DATUM_HASHER_WORK_SIZE];
	uint8_t from_work[32];
	uint8_t from_header[32];
	uint8_t zeros[16];

	memset(&h, 0, sizeof(h));
	h.flags = 0;
	h.nTime = 2000000000;
	h.nBits = 486604799;
	h.nNonce = 1;
	h.nonce2 = 2;
	h.height = 1;
	h.txcount = 1;
	memset(h.hashPrevBlock, 0x11, 32);
	memset(h.hashMerkleRoot, 0x22, 32);
	/* mill-shaped extraNonce: 4 zero bytes then extraNonce1||extraNonce2 */
	memset(h.extranonce, 0, 4);
	memset(h.extranonce + 4, 0xa5, 12);

	datum_pow_merge_mining_commitment(&h, commitment);
	datum_pow_coinb1(commitment, coinb1);
	datum_test(coinb1[0] == 0 && coinb1[1] == 0 && coinb1[2] == 0);
	memcpy(en12, h.extranonce + 4, 12);
	datum_test(datum_pow_work_root(coinb1, en12, root));
	datum_pow_prev_hidden(h.hashPrevBlock, prev_hidden);
	pk_u32le(nonce8, 0, h.nNonce);
	pk_u32le(nonce8, 4, h.nonce2);
	pk_u32le(ntime8, 0, h.time_offset);
	pk_u32le(ntime8, 4, h.nonce3);
	datum_pow_work_header(prev_hidden, nonce8, ntime8, root, work);
	memset(zeros, 0, 16);
	datum_pow_asic_pow_hash(work, zeros, 0, from_work);
	datum_pow_header_hash(&h, from_header);
	datum_test(memcmp(from_work, from_header, 32) == 0);

	{
		datum_header_v2_t filled = h;
		uint8_t en1[4];
		uint8_t en2[8];
		memcpy(en1, h.extranonce + 4, 4);
		memcpy(en2, h.extranonce + 8, 8);
		memset(filled.extranonce, 0xff, 16);
		datum_pow_fill_from_submit(&filled, en1, en2, ntime8, nonce8);
		datum_test(filled.nNonce == h.nNonce);
		datum_test(filled.nonce2 == h.nonce2);
		datum_test(memcmp(filled.extranonce, h.extranonce, 16) == 0);
	}
}

void datum_pow_tests(void)
{
	datum_pow_vector_tests();
	datum_pow_hasher_work_tests();
}
