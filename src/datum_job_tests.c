/*
 * Fixture jobs per work kind. No node RPC. Not CONVOY.
 */

#include <stdio.h>
#include <string.h>

#include "datum_job.h"
#include "datum_utils.h"

static void tagged_header(datum_header_v2_t *h, datum_work_kind_t k)
{
	const datum_job_strategy_t *st = datum_job_strategy(k);
	memset(h, 0, sizeof(*h));
	h->nVersion = 4;
	h->nTime = 123;
	h->nBits = 0x207fffff;
	h->nNonce = 99;
	datum_job_apply_kind(h, k);
	st->prepare(h);
}

static bool hash_meets_pow_limit_easy(const uint8_t hash[32])
{
	uint8_t target[32];
	nbits_to_target(0x207fffff, target);
	return compare_hashes(hash, target) <= 0;
}

void datum_job_tests(void)
{
	datum_work_kind_t k;
	datum_header_v2_t h;
	uint8_t d0[32];
	uint8_t d1[32];
	char hex[65];
	const datum_job_strategy_t *st;
	int nonce;

	datum_test(datum_work_kind_parse("blake2b", &k) && k == DATUM_WORK_BLAKE2B);
	datum_test(datum_work_kind_parse("sha256d", &k) && k == DATUM_WORK_SHA256D);
	datum_test(datum_work_kind_parse("fp8gym", &k) && k == DATUM_WORK_FP8GYM);
	datum_test(datum_work_kind_parse("poseidon2", &k) && k == DATUM_WORK_POSEIDON2);
	datum_test(!datum_work_kind_parse("high-hash", &k));
	datum_test(!datum_work_kind_parse("BLAKE2B", &k));

	datum_test(datum_job_subscribe_extra_error(DATUM_WORK_BLAKE2B, NULL) == NULL);
	datum_test(datum_job_subscribe_extra_error(DATUM_WORK_BLAKE2B, "") == NULL);
	datum_test(datum_job_subscribe_extra_error(DATUM_WORK_BLAKE2B, "deadbeef") == NULL);
	datum_test(datum_job_subscribe_extra_error(DATUM_WORK_BLAKE2B, "blake2b") == NULL);
	{
		const char *err = datum_job_subscribe_extra_error(DATUM_WORK_BLAKE2B, "sha256d");
		datum_test(err != NULL && strstr(err, "Blake2b") != NULL);
		datum_test(strstr(err, "high-hash") == NULL);
	}
	{
		const char *err = datum_job_subscribe_extra_error(DATUM_WORK_FP8GYM, "poseidon2");
		datum_test(err != NULL && strstr(err, "FP8") != NULL);
	}

	st = datum_job_strategy(DATUM_WORK_SHA256D);
	datum_test(st->notify_shape == DATUM_NOTIFY_SHA256D);
	datum_test(datum_job_strategy(DATUM_WORK_BLAKE2B)->notify_shape == DATUM_NOTIFY_HASHER);
	datum_test(datum_job_strategy(DATUM_WORK_FP8GYM)->notify_shape == DATUM_NOTIFY_HASHER);
	datum_test(datum_job_strategy(DATUM_WORK_POSEIDON2)->notify_shape == DATUM_NOTIFY_HASHER);

	tagged_header(&h, DATUM_WORK_SHA256D);
	datum_test(datum_job_header_kind_matches(&h, DATUM_WORK_SHA256D));
	datum_test(!datum_job_header_kind_matches(&h, DATUM_WORK_BLAKE2B));
	datum_test(st->digest(&h, d0) == 0);
	h.nonce2 = 1;
	datum_test(!st->tail_ok(&h));
	datum_test(st->digest(&h, d1) == 0);
	datum_test(memcmp(d0, d1, 32) == 0);
	{
		uint8_t blake[32];
		datum_test(datum_job_strategy(DATUM_WORK_BLAKE2B)->digest(&h, blake) == 0);
		datum_test(memcmp(blake, d0, 32) != 0);
	}

	{
		uint32_t job = datum_pow_complete_version(&h);
		datum_test(!datum_job_sha256d_version_roll_locked(job, job));
		datum_test(datum_job_sha256d_version_roll_locked(job, job ^ DATUM_VERSION_HEADER_V2));
		datum_test(datum_job_sha256d_version_roll_locked(job, job ^ 0x00000100u));
		datum_test(datum_job_sha256d_version_roll_locked(job, job ^ 0x00000200u));
		datum_test(!datum_job_sha256d_version_roll_locked(job, job ^ 0x00000004u));
	}

	tagged_header(&h, DATUM_WORK_SHA256D);
	{
		int hits = 0;
		for (nonce = 0; nonce < 256; nonce++) {
			h.nNonce = (uint32_t)nonce;
			datum_test(st->digest(&h, d0) == 0);
			if (hash_meets_pow_limit_easy(d0)) {
				hits = 1;
				break;
			}
		}
		datum_test(hits == 1);
	}

	tagged_header(&h, DATUM_WORK_POSEIDON2);
	datum_test(datum_job_header_kind_matches(&h, DATUM_WORK_POSEIDON2));
	datum_test(datum_job_poseidon2_digest(&h, d0) == 0);
	h.nNonce = 100;
	datum_test(datum_job_poseidon2_digest(&h, d1) == 0);
	datum_test(memcmp(d0, d1, 32) != 0);

	tagged_header(&h, DATUM_WORK_BLAKE2B);
	h.nonce2 = 1;
	datum_test(datum_job_strategy(DATUM_WORK_BLAKE2B)->tail_ok(&h));

	tagged_header(&h, DATUM_WORK_FP8GYM);
	h.nTime = 1;
	h.nNonce = 1;
	datum_test(datum_job_header_kind_matches(&h, DATUM_WORK_FP8GYM));
	datum_test(datum_job_fp8_expand_seed(&h, d0) == 0);
	datum_pow_bytes_to_hex(d0, 32, hex);
	if (!datum_test(strcmp(hex, "1383384b07bda65de7927227a310b4f8bbe481c9eb8ba3ca399518b132cffc59") == 0)) {
		fprintf(stderr, "fp8 seed got %s\n", hex);
	}
	datum_test(datum_job_fp8_digest(&h, d1) == 0);
	datum_pow_u256_to_hex(d1, hex);
	if (!datum_test(strcmp(hex, "20c6e0f0b7da617c84b90b7e090d00c5ae162aa9885ddba00c02b7c859241bd5") == 0)) {
		fprintf(stderr, "fp8 digest got %s\n", hex);
	}
}
