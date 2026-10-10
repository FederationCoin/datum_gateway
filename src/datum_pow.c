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

/* Header-v2 GetHash. Port of cpu-miner-cpp pow.cpp / Knots CBlockHeader::GetHash. Not CONVOY. */

#include "datum_pow.h"

#include <stdlib.h>
#include <string.h>

#include "datum_utils.h"

#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 64

typedef struct {
	uint64_t h[8];
	uint64_t t[2];
	uint64_t f[2];
	uint8_t buf[BLAKE2B_BLOCKBYTES];
	size_t buflen;
	size_t outlen;
} datum_blake2b_state;

static const uint64_t blake2b_IV[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static uint64_t blake2b_load64(const uint8_t *p)
{
	uint64_t x;
	memcpy(&x, p, 8);
	return x;
}

static void blake2b_store64(uint8_t *p, uint64_t x)
{
	memcpy(p, &x, 8);
}

static uint64_t blake2b_rotr64(uint64_t x, unsigned r)
{
	return (x >> r) | (x << (64 - r));
}

static void blake2b_increment_counter(datum_blake2b_state *S, uint64_t inc)
{
	S->t[0] += inc;
	S->t[1] += (S->t[0] < inc);
}

#define G(r, i, a, b, c, d) \
	do { \
		a = a + b + m[blake2b_sigma[r][2 * (i) + 0]]; \
		d = blake2b_rotr64((uint64_t)(d ^ a), 32); \
		c = c + d; \
		b = blake2b_rotr64((uint64_t)(b ^ c), 24); \
		a = a + b + m[blake2b_sigma[r][2 * (i) + 1]]; \
		d = blake2b_rotr64((uint64_t)(d ^ a), 16); \
		c = c + d; \
		b = blake2b_rotr64((uint64_t)(b ^ c), 63); \
	} while (0)

#define ROUND(r) \
	do { \
		G(r, 0, v[0], v[4], v[8], v[12]); \
		G(r, 1, v[1], v[5], v[9], v[13]); \
		G(r, 2, v[2], v[6], v[10], v[14]); \
		G(r, 3, v[3], v[7], v[11], v[15]); \
		G(r, 4, v[0], v[5], v[10], v[15]); \
		G(r, 5, v[1], v[6], v[11], v[12]); \
		G(r, 6, v[2], v[7], v[8], v[13]); \
		G(r, 7, v[3], v[4], v[9], v[14]); \
	} while (0)

static void blake2b_compress(datum_blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES])
{
	uint64_t m[16];
	uint64_t v[16];
	int i;
	for (i = 0; i < 16; ++i) {
		m[i] = blake2b_load64(block + i * 8);
	}
	for (i = 0; i < 8; ++i) {
		v[i] = S->h[i];
	}
	v[8] = blake2b_IV[0];
	v[9] = blake2b_IV[1];
	v[10] = blake2b_IV[2];
	v[11] = blake2b_IV[3];
	v[12] = blake2b_IV[4] ^ S->t[0];
	v[13] = blake2b_IV[5] ^ S->t[1];
	v[14] = blake2b_IV[6] ^ S->f[0];
	v[15] = blake2b_IV[7] ^ S->f[1];
	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);
	ROUND(10);
	ROUND(11);
	for (i = 0; i < 8; ++i) {
		S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
	}
}

#undef G
#undef ROUND

static int blake2b_init(datum_blake2b_state *S, size_t outlen)
{
	uint8_t P[64];
	int i;
	if (!outlen || outlen > BLAKE2B_OUTBYTES) {
		return -1;
	}
	memset(S, 0, sizeof(*S));
	for (i = 0; i < 8; ++i) {
		S->h[i] = blake2b_IV[i];
	}
	memset(P, 0, sizeof(P));
	P[0] = (uint8_t)outlen;
	P[2] = 1;
	P[3] = 1;
	for (i = 0; i < 8; ++i) {
		S->h[i] ^= blake2b_load64(P + i * 8);
	}
	S->outlen = outlen;
	return 0;
}

static int blake2b_update(datum_blake2b_state *S, const uint8_t *in, size_t inlen)
{
	size_t left;
	size_t fill;
	if (inlen == 0) {
		return 0;
	}
	left = S->buflen;
	fill = BLAKE2B_BLOCKBYTES - left;
	if (inlen > fill) {
		S->buflen = 0;
		memcpy(S->buf + left, in, fill);
		blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
		blake2b_compress(S, S->buf);
		in += fill;
		inlen -= fill;
		while (inlen > BLAKE2B_BLOCKBYTES) {
			blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
			blake2b_compress(S, in);
			in += BLAKE2B_BLOCKBYTES;
			inlen -= BLAKE2B_BLOCKBYTES;
		}
	}
	memcpy(S->buf + S->buflen, in, inlen);
	S->buflen += inlen;
	return 0;
}

static int blake2b_final(datum_blake2b_state *S, uint8_t *out, size_t outlen)
{
	uint8_t buffer[BLAKE2B_OUTBYTES];
	int i;
	if (!out || outlen < S->outlen) {
		return -1;
	}
	if (S->f[0] != 0) {
		return -1;
	}
	memset(buffer, 0, sizeof(buffer));
	blake2b_increment_counter(S, S->buflen);
	S->f[0] = (uint64_t)-1;
	memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
	blake2b_compress(S, S->buf);
	for (i = 0; i < 8; ++i) {
		blake2b_store64(buffer + i * 8, S->h[i]);
	}
	memcpy(out, buffer, S->outlen);
	return 0;
}

int datum_pow_blake2b_32(const uint8_t *in, size_t inlen, uint8_t out[32])
{
	datum_blake2b_state S;
	if (blake2b_init(&S, 32) < 0) {
		return -1;
	}
	blake2b_update(&S, in, inlen);
	return blake2b_final(&S, out, 32);
}

void datum_pow_tagged_sha256(const char *tag, const uint8_t *msg, size_t n, uint8_t out[32])
{
	uint8_t taghash[32];
	uint8_t buf[64 + 256];
	uint8_t *heap = NULL;
	uint8_t *p;
	size_t taglen = strlen(tag);
	size_t total = 64 + n;
	my_sha256(taghash, tag, taglen);
	if (total <= sizeof(buf)) {
		p = buf;
	} else {
		heap = malloc(total);
		p = heap;
		if (!p) {
			memset(out, 0, 32);
			return;
		}
	}
	memcpy(p, taghash, 32);
	memcpy(p + 32, taghash, 32);
	if (n) {
		memcpy(p + 64, msg, n);
	}
	my_sha256(out, p, total);
	if (heap) {
		free(heap);
	}
}

static void u256_reverse(uint8_t v[32])
{
	int i;
	for (i = 0; i < 16; ++i) {
		uint8_t t = v[i];
		v[i] = v[31 - i];
		v[31 - i] = t;
	}
}

static bool xor_key_is_null(const uint8_t k[16])
{
	int i;
	for (i = 0; i < 16; ++i) {
		if (k[i]) {
			return false;
		}
	}
	return true;
}

static void xor_key_mask_bytes(const uint8_t xor_key[16], uint8_t clear_bits, uint8_t mask[32])
{
	unsigned clear_bytes;
	memset(mask, 0, 32);
	if (xor_key_is_null(xor_key)) {
		return;
	}
	datum_pow_tagged_sha256("Bitcoin block hash PoW XOR mask", xor_key, 16, mask);
	clear_bytes = clear_bits / 8;
	if (clear_bytes > 32) {
		clear_bytes = 32;
	}
	memset(mask, 0, clear_bytes);
	if (clear_bytes < 32) {
		mask[clear_bytes] &= (uint8_t)(0xffu >> (clear_bits % 8));
	}
}

uint32_t datum_pow_complete_version(const datum_header_v2_t *h)
{
	return DATUM_VERSION_HEADER_V2 | ((uint32_t)h->nVersion & ~DATUM_VERSION_HEADER_V2);
}

uint32_t datum_pow_time_on_wire(const datum_header_v2_t *h)
{
	if ((h->flags & DATUM_FLAG_TIME_OFFSET) == 0) {
		return h->nTime;
	}
	return h->nTime - h->time_offset;
}

void datum_pow_serialize_header(const datum_header_v2_t *h, uint8_t out[DATUM_HEADER_V2_SIZE])
{
	memset(out, 0, DATUM_HEADER_V2_SIZE);
	pk_u32le(out, 0, datum_pow_complete_version(h));
	memcpy(out + 4, h->hashPrevBlock, 32);
	memcpy(out + 36, h->hashMerkleRoot, 32);
	pk_u32le(out, 68, datum_pow_time_on_wire(h));
	pk_u32le(out, 72, h->nBits);
	pk_u32le(out, 76, h->nNonce);
	pk_u32le(out, 80, h->nonce2);
	pk_u32le(out, 84, h->nonce3);
	memcpy(out + 88, h->extranonce, 16);
	pk_u32le(out, 104, h->time_offset);
	pk_u16le(out, 108, h->txcount);
	out[110] = h->flags;
	out[111] = h->xor_key_mask_clear_bits;
	memcpy(out + 112, h->xor_key, 16);
	pk_u32le(out, 128, (uint32_t)h->height);
	memcpy(out + 132, h->mm_rhs, 32);
}

bool datum_pow_deserialize_header(const uint8_t in[DATUM_HEADER_V2_SIZE], datum_header_v2_t *h)
{
	uint32_t v = upk_u32le(in, 0);
	uint32_t wire;
	if ((v & DATUM_VERSION_HEADER_V2) == 0) {
		return false;
	}
	memset(h, 0, sizeof(*h));
	h->nVersion = (int32_t)(v & ~DATUM_VERSION_HEADER_V2);
	memcpy(h->hashPrevBlock, in + 4, 32);
	memcpy(h->hashMerkleRoot, in + 36, 32);
	wire = upk_u32le(in, 68);
	h->nBits = upk_u32le(in, 72);
	h->nNonce = upk_u32le(in, 76);
	h->nonce2 = upk_u32le(in, 80);
	h->nonce3 = upk_u32le(in, 84);
	memcpy(h->extranonce, in + 88, 16);
	h->time_offset = upk_u32le(in, 104);
	h->txcount = upk_u16le(in, 108);
	h->flags = in[110];
	h->xor_key_mask_clear_bits = in[111];
	memcpy(h->xor_key, in + 112, 16);
	h->height = (int32_t)upk_u32le(in, 128);
	memcpy(h->mm_rhs, in + 132, 32);
	if (h->flags & DATUM_FLAG_TIME_OFFSET) {
		h->nTime = wire + h->time_offset;
	} else {
		h->nTime = wire;
	}
	return true;
}

void datum_pow_merge_mining_commitment(const datum_header_v2_t *h, uint8_t out[32])
{
	uint8_t xor_key_hash[32];
	uint8_t prev_ordered[32];
	uint8_t h1[119];
	uint8_t h1_hash[32];
	uint8_t h2[96];
	size_t o = 0;

	datum_pow_tagged_sha256("Bitcoin block hash PoW XOR key", h->xor_key, 16, xor_key_hash);
	memcpy(prev_ordered, h->hashPrevBlock, 32);
	u256_reverse(prev_ordered);

	pk_u32le(h1, (int)o, datum_pow_complete_version(h));
	o += 4;
	memcpy(h1 + o, prev_ordered, 32);
	o += 32;
	pk_u32le(h1, (int)o, (uint32_t)h->height);
	o += 4;
	memcpy(h1 + o, h->hashMerkleRoot, 32);
	o += 32;
	pk_u32le(h1, (int)o, datum_pow_time_on_wire(h));
	o += 4;
	h1[o++] = 0;
	pk_u32le(h1, (int)o, h->nBits);
	o += 4;
	pk_u32le(h1, (int)o, (uint32_t)h->txcount);
	o += 4;
	h1[o++] = h->flags;
	h1[o++] = h->xor_key_mask_clear_bits;
	memcpy(h1 + o, xor_key_hash, 32);

	datum_pow_tagged_sha256("Bitcoin block header 1", h1, 119, h1_hash);
	memset(h2, 0, 96);
	memcpy(h2, h1_hash, 32);
	memcpy(h2 + 64, h->mm_rhs, 32);
	datum_pow_tagged_sha256("Merge-mining hook", h2, 96, out);
}

void datum_pow_prev_hidden(const uint8_t hashPrevBlock[32], uint8_t out[32])
{
	uint8_t prev_ordered[32];
	memcpy(prev_ordered, hashPrevBlock, 32);
	u256_reverse(prev_ordered);
	datum_pow_tagged_sha256("Bitcoin prevblock header, hashed", prev_ordered, 32, out);
	memset(out, 0, 6);
}

int datum_pow_asic_preimage(const datum_header_v2_t *h, uint8_t *out, size_t out_max)
{
	uint8_t h2_hash[32];
	uint8_t leaf[52];
	uint8_t work_root[32];
	uint8_t prev_hidden[32];
	size_t n = 0;

	datum_pow_merge_mining_commitment(h, h2_hash);
	memset(leaf, 0, 52);
	memcpy(leaf + 4, h2_hash, 32);
	memcpy(leaf + 36, h->extranonce, 16);
	if (datum_pow_blake2b_32(leaf, 52, work_root) != 0) {
		return -1;
	}

	switch (h->flags & 3) {
		case 3:
			if (out_max < 32) {
				return -1;
			}
			memset(out + n, 0, 32);
			n += 32;
			/* fall through */
		case 2:
			if (out_max < n + 48 + 32 + 16 + 32) {
				return -1;
			}
			memset(out + n, 0, 48);
			n += 48;
			memcpy(out + n, h2_hash, 32);
			n += 32;
			pk_u32le(out, (int)n, h->nNonce);
			n += 4;
			pk_u32le(out, (int)n, h->nonce2);
			n += 4;
			pk_u32le(out, (int)n, h->time_offset);
			n += 4;
			pk_u32le(out, (int)n, h->nonce3);
			n += 4;
			memcpy(out + n, work_root, 32);
			n += 32;
			break;
		case 0:
			if (out_max < 80) {
				return -1;
			}
			datum_pow_prev_hidden(h->hashPrevBlock, prev_hidden);
			memcpy(out + n, prev_hidden, 32);
			n += 32;
			pk_u32le(out, (int)n, h->nNonce);
			n += 4;
			pk_u32le(out, (int)n, h->nonce2);
			n += 4;
			pk_u32le(out, (int)n, h->time_offset);
			n += 4;
			pk_u32le(out, (int)n, h->nonce3);
			n += 4;
			memcpy(out + n, work_root, 32);
			n += 32;
			break;
		case 1:
			if (out_max < 80) {
				return -1;
			}
			pk_u32le(out, (int)n, h->nNonce);
			n += 4;
			pk_u32le(out, (int)n, h->nonce2);
			n += 4;
			pk_u32le(out, (int)n, h->nonce3);
			n += 4;
			pk_u32le(out, (int)n, h->time_offset);
			n += 4;
			memcpy(out + n, work_root, 32);
			n += 32;
			memcpy(out + n, h2_hash, 32);
			n += 32;
			break;
	}
	return (int)n;
}

void datum_pow_header_hash(const datum_header_v2_t *h, uint8_t out[32])
{
	uint8_t asic[256];
	uint8_t hash[32];
	uint8_t mask[32];
	int n;
	size_t i;
	n = datum_pow_asic_preimage(h, asic, sizeof(asic));
	if (n <= 0) {
		memset(out, 0, 32);
		return;
	}
	datum_pow_blake2b_32(asic, (size_t)n, hash);
	xor_key_mask_bytes(h->xor_key, h->xor_key_mask_clear_bits, mask);
	for (i = 0; i < 32; ++i) {
		out[31 - i] = (uint8_t)(hash[i] ^ mask[i]);
	}
}

void datum_pow_coinb1(const uint8_t commitment[32], uint8_t out[DATUM_HASHER_COINB1_SIZE])
{
	memset(out, 0, 3);
	memcpy(out + 3, commitment, 32);
	memset(out + 35, 0, 4);
}

bool datum_pow_work_root(const uint8_t coinb1[DATUM_HASHER_COINB1_SIZE], const uint8_t extranonce12[12], uint8_t root[32])
{
	uint8_t leaf[52];
	leaf[0] = 0;
	memcpy(leaf + 1, coinb1, DATUM_HASHER_COINB1_SIZE);
	memcpy(leaf + 40, extranonce12, 12);
	return datum_pow_blake2b_32(leaf, 52, root) == 0;
}

void datum_pow_work_header(const uint8_t prev_hidden[32], const uint8_t nonce8[8], const uint8_t ntime8[8], const uint8_t root[32], uint8_t work[DATUM_HASHER_WORK_SIZE])
{
	memcpy(work, prev_hidden, 32);
	memcpy(work + 32, nonce8, 8);
	memcpy(work + 40, ntime8, 8);
	memcpy(work + 48, root, 32);
}

void datum_pow_asic_pow_hash(const uint8_t work[DATUM_HASHER_WORK_SIZE], const uint8_t xor_key[16], uint8_t xor_clear_bits, uint8_t out[32])
{
	uint8_t hash[32];
	uint8_t xor_key_mask[32];
	int i;
	datum_pow_blake2b_32(work, DATUM_HASHER_WORK_SIZE, hash);
	xor_key_mask_bytes(xor_key, xor_clear_bits, xor_key_mask);
	for (i = 0; i < 32; ++i) {
		out[31 - i] = (uint8_t)(hash[i] ^ xor_key_mask[i]);
	}
}

void datum_pow_fill_from_submit(datum_header_v2_t *h, const uint8_t extra_nonce1[4], const uint8_t extra_nonce2[8], const uint8_t ntime8[8], const uint8_t nonce8[8])
{
	h->nNonce = upk_u32le(nonce8, 0);
	h->nonce2 = upk_u32le(nonce8, 4);
	h->time_offset = upk_u32le(ntime8, 0);
	h->nonce3 = upk_u32le(ntime8, 4);
	memset(h->extranonce, 0, 4);
	memcpy(h->extranonce + 4, extra_nonce1, 4);
	memcpy(h->extranonce + 8, extra_nonce2, 8);
}

void datum_pow_bytes_to_hex(const uint8_t *p, size_t n, char *hex)
{
	static const char *k = "0123456789abcdef";
	size_t i;
	for (i = 0; i < n; ++i) {
		hex[2 * i] = k[p[i] >> 4];
		hex[2 * i + 1] = k[p[i] & 0xf];
	}
	hex[2 * n] = 0;
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

bool datum_pow_parse_hex(const char *hex, uint8_t *out, size_t out_len)
{
	size_t i;
	size_t n;
	if (!hex) {
		return false;
	}
	n = strlen(hex);
	if (n != out_len * 2) {
		return false;
	}
	for (i = 0; i < out_len; ++i) {
		int a = hex_nibble(hex[2 * i]);
		int b = hex_nibble(hex[2 * i + 1]);
		if (a < 0 || b < 0) {
			return false;
		}
		out[i] = (uint8_t)((a << 4) | b);
	}
	return true;
}

bool datum_pow_u256_from_hex(const char *hex, uint8_t out[32])
{
	uint8_t raw[32];
	int i;
	if (!datum_pow_parse_hex(hex, raw, 32)) {
		return false;
	}
	for (i = 0; i < 32; ++i) {
		out[i] = raw[31 - i];
	}
	return true;
}

bool datum_pow_u128_from_hex_reversed(const char *hex, uint8_t out[16])
{
	uint8_t raw[16];
	int i;
	if (!datum_pow_parse_hex(hex, raw, 16)) {
		return false;
	}
	for (i = 0; i < 16; ++i) {
		out[i] = raw[15 - i];
	}
	return true;
}

void datum_pow_u256_to_hex(const uint8_t v[32], char hex[65])
{
	uint8_t disp[32];
	int i;
	for (i = 0; i < 32; ++i) {
		disp[i] = v[31 - i];
	}
	datum_pow_bytes_to_hex(disp, 32, hex);
}

void datum_pow_header_hash_hex(const datum_header_v2_t *h, char hex[65])
{
	uint8_t hash[32];
	datum_pow_header_hash(h, hash);
	datum_pow_u256_to_hex(hash, hex);
}
