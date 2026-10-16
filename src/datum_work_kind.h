/*
 * Closed work-kind set. Same GBT names as the node. Not CONVOY.
 */

#ifndef _DATUM_WORK_KIND_H_
#define _DATUM_WORK_KIND_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "datum_pow.h"

#define DATUM_VERSION_WORK_RESERVED_MASK 0x0fffcc00u
#define DATUM_SHA256D_VERSION_LOCK_MASK (DATUM_VERSION_WORK_KIND_MASK | DATUM_VERSION_HEADER_V2)

typedef enum {
	DATUM_WORK_BLAKE2B = 0,
	DATUM_WORK_SHA256D = 1,
	DATUM_WORK_FP8GYM = 2,
	DATUM_WORK_POSEIDON2 = 3,
} datum_work_kind_t;

/* GBT / subscribe token: blake2b, sha256d, fp8gym, poseidon2 */
bool datum_work_kind_parse(const char *s, datum_work_kind_t *out);
const char *datum_work_kind_gbt_name(datum_work_kind_t k);
/* User-facing: Blake2b, SHA-256d, FP8 gym, Poseidon2 */
const char *datum_work_kind_english(datum_work_kind_t k);

#endif
