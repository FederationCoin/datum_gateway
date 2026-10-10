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

#ifndef _DATUM_POW_H_
#define _DATUM_POW_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* FederationCoin header-v2 GetHash. Profile 0, null XOR key. Not CONVOY. */

#define DATUM_VERSION_HEADER_V2 0x80000000u
#define DATUM_FLAG_TIME_OFFSET 4
#define DATUM_HEADER_V2_SIZE 164
#define DATUM_HASHER_COINB1_SIZE 39
#define DATUM_HASHER_WORK_SIZE 80
#define DATUM_EXTRA_NONCE1_SIZE 4
#define DATUM_EXTRA_NONCE2_SIZE 8

typedef struct {
	int32_t nVersion;
	uint8_t hashPrevBlock[32];
	uint8_t hashMerkleRoot[32];
	uint32_t nTime;
	uint32_t nBits;
	uint32_t nNonce;
	uint32_t nonce2;
	uint32_t nonce3;
	uint8_t extranonce[16];
	uint32_t time_offset;
	uint16_t txcount;
	uint8_t flags;
	uint8_t xor_key_mask_clear_bits;
	uint8_t xor_key[16];
	int32_t height;
	uint8_t mm_rhs[32];
} datum_header_v2_t;

uint32_t datum_pow_complete_version(const datum_header_v2_t *h);
uint32_t datum_pow_time_on_wire(const datum_header_v2_t *h);

void datum_pow_serialize_header(const datum_header_v2_t *h, uint8_t out[DATUM_HEADER_V2_SIZE]);
bool datum_pow_deserialize_header(const uint8_t in[DATUM_HEADER_V2_SIZE], datum_header_v2_t *h);

void datum_pow_tagged_sha256(const char *tag, const uint8_t *msg, size_t n, uint8_t out[32]);
int datum_pow_blake2b_32(const uint8_t *in, size_t inlen, uint8_t out[32]);

void datum_pow_merge_mining_commitment(const datum_header_v2_t *h, uint8_t out[32]);
int datum_pow_asic_preimage(const datum_header_v2_t *h, uint8_t *out, size_t out_max);
void datum_pow_header_hash(const datum_header_v2_t *h, uint8_t out[32]);

void datum_pow_prev_hidden(const uint8_t hashPrevBlock[32], uint8_t out[32]);
void datum_pow_coinb1(const uint8_t commitment[32], uint8_t out[DATUM_HASHER_COINB1_SIZE]);
bool datum_pow_work_root(const uint8_t coinb1[DATUM_HASHER_COINB1_SIZE], const uint8_t extranonce12[12], uint8_t root[32]);
void datum_pow_work_header(const uint8_t prev_hidden[32], const uint8_t nonce8[8], const uint8_t ntime8[8], const uint8_t root[32], uint8_t work[DATUM_HASHER_WORK_SIZE]);
void datum_pow_asic_pow_hash(const uint8_t work[DATUM_HASHER_WORK_SIZE], const uint8_t xor_key[16], uint8_t xor_clear_bits, uint8_t out[32]);

void datum_pow_fill_from_submit(datum_header_v2_t *h, const uint8_t extra_nonce1[4], const uint8_t extra_nonce2[8], const uint8_t ntime8[8], const uint8_t nonce8[8]);

void datum_pow_header_hash_hex(const datum_header_v2_t *h, char hex[65]);
void datum_pow_bytes_to_hex(const uint8_t *p, size_t n, char *hex);
bool datum_pow_parse_hex(const char *hex, uint8_t *out, size_t out_len);
bool datum_pow_u256_from_hex(const char *hex, uint8_t out[32]);
bool datum_pow_u128_from_hex_reversed(const char *hex, uint8_t out[16]);
void datum_pow_u256_to_hex(const uint8_t v[32], char hex[65]);

void datum_pow_tests(void);

#endif
