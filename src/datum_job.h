/*
 * Four Stratum job strategies. Declared kind, then that digest. Not CONVOY.
 */

#ifndef _DATUM_JOB_H_
#define _DATUM_JOB_H_

#include "datum_pow.h"
#include "datum_work_kind.h"

typedef enum {
	DATUM_NOTIFY_HASHER = 0,
	DATUM_NOTIFY_SHA256D = 1,
} datum_notify_shape_t;

typedef struct datum_job_strategy {
	datum_work_kind_t kind;
	datum_notify_shape_t notify_shape;
	void (*prepare)(datum_header_v2_t *h);
	bool (*tail_ok)(const datum_header_v2_t *h);
	int (*digest)(const datum_header_v2_t *h, uint8_t out[32]);
	void (*apply_submit)(datum_header_v2_t *h, const uint8_t extra_nonce1[4], const uint8_t extra_nonce2[8], const uint8_t ntime8[8], const uint8_t nonce8[8]);
} datum_job_strategy_t;

const datum_job_strategy_t *datum_job_strategy(datum_work_kind_t k);

void datum_job_apply_kind(datum_header_v2_t *h, datum_work_kind_t k);
bool datum_job_header_kind_matches(const datum_header_v2_t *h, datum_work_kind_t k);

/* True if rolled flips bits 8–9 or bit 31 vs the job version. */
bool datum_job_sha256d_version_roll_locked(uint32_t job_complete, uint32_t rolled);

/*
 * Hasher mill: extraNonce + ntime8 + nonce8 overlay.
 * SHA-256d: nTime/nNonce from the first four bytes; tail stays zero.
 */
void datum_job_apply_submit(datum_header_v2_t *h, datum_work_kind_t k, const uint8_t extra_nonce1[4], const uint8_t extra_nonce2[8], const uint8_t ntime8[8], const uint8_t nonce8[8]);

/* NULL if extra is absent, a session id, or the kind this gateway serves. */
const char *datum_job_subscribe_extra_error(datum_work_kind_t serving, const char *extra);

int datum_job_poseidon2_digest(const datum_header_v2_t *h, uint8_t out[32]);
int datum_job_fp8_digest(const datum_header_v2_t *h, uint8_t out[32]);
int datum_job_fp8_expand_seed(const datum_header_v2_t *h, uint8_t seed[32]);

void datum_job_tests(void);

#endif
