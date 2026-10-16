/*
 * Four Stratum job strategies. Declared kind, then that digest. Not CONVOY.
 */

#include "datum_job.h"

#include <string.h>

#include "datum_utils.h"

static bool bytes_zero(const uint8_t *p, size_t n)
{
	size_t i;
	for (i = 0; i < n; ++i) {
		if (p[i]) {
			return false;
		}
	}
	return true;
}

static void prepare_blake2b(datum_header_v2_t *h)
{
	memset(h->xor_key, 0, sizeof(h->xor_key));
	h->xor_key_mask_clear_bits = 0;
}

static bool tail_blake2b(const datum_header_v2_t *h)
{
	(void)h;
	return true;
}

static int digest_blake2b(const datum_header_v2_t *h, uint8_t out[32])
{
	datum_pow_header_hash(h, out);
	return 0;
}

static void prepare_sha256d(datum_header_v2_t *h)
{
	h->nonce2 = 0;
	h->nonce3 = 0;
	memset(h->extranonce, 0, 16);
	h->time_offset = 0;
	h->flags = 0;
	memset(h->xor_key, 0, sizeof(h->xor_key));
	h->xor_key_mask_clear_bits = 0;
	memset(h->mm_rhs, 0, 32);
}

static bool tail_sha256d(const datum_header_v2_t *h)
{
	return h->nonce2 == 0 && h->nonce3 == 0 && bytes_zero(h->extranonce, 16) && h->time_offset == 0 && h->flags == 0 && bytes_zero(h->xor_key, 16) && h->xor_key_mask_clear_bits == 0 && bytes_zero(h->mm_rhs, 32);
}

static int digest_sha256d(const datum_header_v2_t *h, uint8_t out[32])
{
	uint8_t ser[DATUM_HEADER_V2_SIZE];
	datum_pow_serialize_header(h, ser);
	if (!double_sha256(out, ser, 80)) {
		return -1;
	}
	return 0;
}

static void apply_submit_hasher(datum_header_v2_t *h, const uint8_t extra_nonce1[4], const uint8_t extra_nonce2[8], const uint8_t ntime8[8], const uint8_t nonce8[8])
{
	datum_pow_fill_from_submit(h, extra_nonce1, extra_nonce2, ntime8, nonce8);
}

static void apply_submit_sha256d(datum_header_v2_t *h, const uint8_t extra_nonce1[4], const uint8_t extra_nonce2[8], const uint8_t ntime8[8], const uint8_t nonce8[8])
{
	(void)extra_nonce1;
	(void)extra_nonce2;
	h->nNonce = upk_u32le(nonce8, 0);
	if (ntime8[0] || ntime8[1] || ntime8[2] || ntime8[3]) {
		h->nTime = upk_u32le(ntime8, 0);
	}
}

static void prepare_fp8(datum_header_v2_t *h)
{
	h->flags = 0;
	h->time_offset = 0;
	memset(h->xor_key, 0, sizeof(h->xor_key));
	h->xor_key_mask_clear_bits = 0;
	memset(h->mm_rhs, 0, 32);
}

static bool tail_fp8(const datum_header_v2_t *h)
{
	return h->flags == 0 && h->time_offset == 0 && bytes_zero(h->xor_key, 16) && h->xor_key_mask_clear_bits == 0 && bytes_zero(h->mm_rhs, 32);
}

static void prepare_poseidon2(datum_header_v2_t *h)
{
	h->flags = 0;
	memset(h->xor_key, 0, sizeof(h->xor_key));
	h->xor_key_mask_clear_bits = 0;
}

static bool tail_poseidon2(const datum_header_v2_t *h)
{
	return h->flags == 0 && bytes_zero(h->xor_key, 16) && h->xor_key_mask_clear_bits == 0;
}

static const datum_job_strategy_t STRATEGIES[4] = {
	{
		.kind = DATUM_WORK_BLAKE2B,
		.notify_shape = DATUM_NOTIFY_HASHER,
		.prepare = prepare_blake2b,
		.tail_ok = tail_blake2b,
		.digest = digest_blake2b,
		.apply_submit = apply_submit_hasher,
	},
	{
		.kind = DATUM_WORK_SHA256D,
		.notify_shape = DATUM_NOTIFY_SHA256D,
		.prepare = prepare_sha256d,
		.tail_ok = tail_sha256d,
		.digest = digest_sha256d,
		.apply_submit = apply_submit_sha256d,
	},
	{
		.kind = DATUM_WORK_FP8GYM,
		.notify_shape = DATUM_NOTIFY_HASHER,
		.prepare = prepare_fp8,
		.tail_ok = tail_fp8,
		.digest = datum_job_fp8_digest,
		.apply_submit = apply_submit_hasher,
	},
	{
		.kind = DATUM_WORK_POSEIDON2,
		.notify_shape = DATUM_NOTIFY_HASHER,
		.prepare = prepare_poseidon2,
		.tail_ok = tail_poseidon2,
		.digest = datum_job_poseidon2_digest,
		.apply_submit = apply_submit_hasher,
	},
};

const datum_job_strategy_t *datum_job_strategy(datum_work_kind_t k)
{
	unsigned t = (unsigned)k;
	if (t > 3) {
		return &STRATEGIES[0];
	}
	return &STRATEGIES[t];
}

void datum_job_apply_kind(datum_header_v2_t *h, datum_work_kind_t k)
{
	uint32_t v = (uint32_t)h->nVersion & ~DATUM_VERSION_HEADER_V2;
	v &= ~DATUM_VERSION_WORK_KIND_MASK;
	v |= ((uint32_t)k << DATUM_VERSION_WORK_KIND_SHIFT);
	if ((v & 0x7fffffffu) < 4) {
		v = (v & ~0xffu) | 4;
	}
	h->nVersion = (int32_t)v;
}

bool datum_job_header_kind_matches(const datum_header_v2_t *h, datum_work_kind_t k)
{
	uint32_t v = datum_pow_complete_version(h);
	if ((v & DATUM_VERSION_HEADER_V2) == 0) {
		return false;
	}
	if (v & DATUM_VERSION_WORK_RESERVED_MASK) {
		return false;
	}
	return ((v >> DATUM_VERSION_WORK_KIND_SHIFT) & 3u) == (uint32_t)k;
}

bool datum_job_sha256d_version_roll_locked(uint32_t job_complete, uint32_t rolled)
{
	return ((job_complete ^ rolled) & DATUM_SHA256D_VERSION_LOCK_MASK) != 0;
}

void datum_job_apply_submit(datum_header_v2_t *h, datum_work_kind_t k, const uint8_t extra_nonce1[4], const uint8_t extra_nonce2[8], const uint8_t ntime8[8], const uint8_t nonce8[8])
{
	const datum_job_strategy_t *st = datum_job_strategy(k);
	st->prepare(h);
	st->apply_submit(h, extra_nonce1, extra_nonce2, ntime8, nonce8);
}

const char *datum_job_subscribe_extra_error(datum_work_kind_t serving, const char *extra)
{
	datum_work_kind_t named;
	if (!extra || extra[0] == 0) {
		return NULL;
	}
	if (!datum_work_kind_parse(extra, &named)) {
		return NULL;
	}
	if (named == serving) {
		return NULL;
	}
	return datum_work_kind_english(serving);
}
