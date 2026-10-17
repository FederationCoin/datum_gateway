/*
 * Closed work-kind set. Same GBT names as the node. Not CONVOY.
 */

#include "datum_pow.h"
#include "datum_work_kind.h"

#include <string.h>

bool datum_work_kind_parse(const char *s, datum_work_kind_t *out)
{
	if (!s || !out) {
		return false;
	}
	if (strcmp(s, "blake2b") == 0) {
		*out = DATUM_WORK_BLAKE2B;
		return true;
	}
	if (strcmp(s, "sha256d") == 0) {
		*out = DATUM_WORK_SHA256D;
		return true;
	}
	if (strcmp(s, "fp8gym") == 0) {
		*out = DATUM_WORK_FP8GYM;
		return true;
	}
	if (strcmp(s, "poseidon2") == 0) {
		*out = DATUM_WORK_POSEIDON2;
		return true;
	}
	return false;
}

const char *datum_work_kind_gbt_name(datum_work_kind_t k)
{
	switch (k) {
		case DATUM_WORK_BLAKE2B:
			return "blake2b";
		case DATUM_WORK_SHA256D:
			return "sha256d";
		case DATUM_WORK_FP8GYM:
			return "fp8gym";
		case DATUM_WORK_POSEIDON2:
			return "poseidon2";
	}
	return "blake2b";
}

const char *datum_work_kind_english(datum_work_kind_t k)
{
	switch (k) {
		case DATUM_WORK_BLAKE2B:
			return "Blake2b";
		case DATUM_WORK_SHA256D:
			return "SHA-256d";
		case DATUM_WORK_FP8GYM:
			return "FP8 gym";
		case DATUM_WORK_POSEIDON2:
			return "Poseidon2";
	}
	return "Blake2b";
}
