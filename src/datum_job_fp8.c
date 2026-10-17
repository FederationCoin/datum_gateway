/*
 * FP8 gym digest. Port of federation-pool fp8-gym.ts / node fp8_gym.cpp. Do not retune MMA. Not CONVOY.
 */

#include "datum_job.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "datum_utils.h"

#define FP8_DIM 256
#define FP8_TILE_M 16
#define FP8_TILE_N 8
#define FP8_TILE_K 32
#define FP8_MT 16
#define FP8_NT 32
#define FP8_KT 8
#define FP8_MATRIX_BYTES (FP8_DIM * FP8_DIM)
#define FP8_FDA_FRAC 25

static const uint8_t EXPAND_DOMAIN[16] = "gfcn-fp8-gym-v2";
static const uint8_t OUT_DOMAIN[] = "gfcn-fp8-gym-out-v2";

typedef struct {
	bool valid;
	bool zero;
	bool neg;
	int exp;
	int mag3;
} e4_term;

static e4_term parse_e4m3fn(uint8_t b)
{
	e4_term t;
	unsigned s = (b >> 7) & 1;
	unsigned e = (b >> 3) & 15;
	unsigned m = b & 7;
	t.valid = true;
	t.zero = false;
	t.neg = s != 0;
	t.exp = 0;
	t.mag3 = 0;
	if (e == 15 && m == 7) {
		t.valid = false;
		return t;
	}
	if (e == 0 && m == 0) {
		t.zero = true;
		return t;
	}
	if (e == 0) {
		t.exp = -6;
		t.mag3 = (int)m;
		return t;
	}
	t.exp = (int)e - 7;
	t.mag3 = 8 + (int)m;
	return t;
}

static uint32_t float_to_bits(float x)
{
	uint32_t u;
	memcpy(&u, &x, 4);
	return u;
}

static float bits_to_float(uint32_t u)
{
	float x;
	memcpy(&x, &u, 4);
	return x;
}

static int clz64(uint64_t mag)
{
	if (mag == 0) {
		return 64;
	}
	return __builtin_clzll(mag);
}

static float decode_e4m3fn_f(uint8_t b)
{
	e4_term t = parse_e4m3fn(b);
	float mag;
	if (!t.valid) {
		return NAN;
	}
	if (t.zero) {
		return 0.f;
	}
	mag = ldexpf((float)t.mag3, t.exp - 3);
	return t.neg ? -mag : mag;
}

static uint8_t quantize_e4m3fn(float x)
{
	uint32_t u = float_to_bits(x);
	bool neg = (u >> 31) != 0;
	unsigned e = (u >> 23) & 255;
	unsigned m = u & 0x7fffff;
	float mag;
	int code;
	int best = 0;
	float best_dist = INFINITY;
	int best_mant = 0;
	if (e == 255) {
		if (m != 0) {
			return neg ? 0xff : 0x7f;
		}
		return neg ? 0xfe : 0x7e;
	}
	if (e == 0 && m == 0) {
		return neg ? 0x80 : 0x00;
	}
	mag = fabsf(x);
	if (mag > 448.f) {
		return neg ? 0xfe : 0x7e;
	}
	for (code = 0; code <= 0x7e; code++) {
		float decoded = decode_e4m3fn_f((uint8_t)code);
		float d;
		int mant;
		if (isnan(decoded)) {
			continue;
		}
		d = fabsf(mag - decoded);
		mant = code & 7;
		if (d < best_dist) {
			best_dist = d;
			best = code;
			best_mant = mant;
		} else if (d == best_dist) {
			if (mant % 2 == 0 && best_mant % 2 != 0) {
				best = code;
				best_mant = mant;
			} else if (mant % 2 == 0 && best_mant % 2 == 0 && code < best) {
				best = code;
				best_mant = mant;
			}
		}
	}
	if (best == 0) {
		return neg ? 0x80 : 0x00;
	}
	return neg ? (uint8_t)(best | 0x80) : (uint8_t)best;
}

static float normalize_rz_fp32(__int128 signed_mag, int scale)
{
	bool neg;
	uint64_t mag;
	int k;
	int unb;
	uint32_t bits;
	if (signed_mag == 0) {
		return 0.f;
	}
	neg = signed_mag < 0;
	mag = (uint64_t)(neg ? -signed_mag : signed_mag);
	k = 63 - clz64(mag);
	unb = scale + k;
	bits = neg ? 0x80000000u : 0;
	if (unb >= 128) {
		bits |= 0x7f800000u;
		return bits_to_float(bits);
	}
	if (unb <= -127) {
		int sl = scale + 149;
		uint64_t stored = 0;
		if (sl >= 0) {
			if (sl >= 64) {
				stored = 0;
			} else {
				uint64_t shifted = mag << sl;
				stored = (shifted >> sl) == mag ? shifted : 0;
			}
		} else {
			int sr = -sl;
			stored = sr >= 64 ? 0 : mag >> sr;
		}
		if (stored >= (1ULL << 23)) {
			stored = (1ULL << 23) - 1;
		}
		bits |= (uint32_t)stored;
		return bits_to_float(bits);
	}
	{
		uint32_t mant24;
		if (k >= 23) {
			mant24 = (uint32_t)(mag >> (unsigned)(k - 23));
		} else {
			mant24 = (uint32_t)(mag << (unsigned)(23 - k));
		}
		bits |= ((uint32_t)(unb + 127) << 23) | (mant24 & 0x7fffff);
		return bits_to_float(bits);
	}
}

typedef struct {
	bool nan;
	bool inf;
	bool neg;
	bool zero;
	int exp;
	uint64_t sig;
} unpack_fp32;

static unpack_fp32 unpack_c(float c)
{
	unpack_fp32 u;
	uint32_t bits = float_to_bits(c);
	unsigned e = (bits >> 23) & 255;
	unsigned m = bits & 0x7fffff;
	memset(&u, 0, sizeof(u));
	u.neg = (bits >> 31) != 0;
	if (e == 255) {
		u.nan = m != 0;
		u.inf = m == 0;
		return u;
	}
	if (e == 0 && m == 0) {
		u.zero = true;
		return u;
	}
	if (e == 0) {
		u.exp = -126;
		u.sig = ((uint64_t)m) << (FP8_FDA_FRAC - 23);
		return u;
	}
	u.exp = (int)e - 127;
	u.sig = (0x800000ULL + (uint64_t)m) << (FP8_FDA_FRAC - 23);
	return u;
}

typedef struct {
	bool zero;
	bool neg;
	int exp;
	uint64_t sig;
} prod_term;

static int qmma_k32(const uint8_t aK[FP8_TILE_K], const uint8_t bK[FP8_TILE_K], float c, float *out)
{
	prod_term prods[FP8_TILE_K];
	unpack_fp32 unpacked;
	int k;
	bool any;
	int e_max;
	__int128 acc = 0;
	unpacked = unpack_c(c);
	if (unpacked.nan) {
		*out = NAN;
		return 0;
	}
	if (unpacked.inf) {
		*out = unpacked.neg ? -INFINITY : INFINITY;
		return 0;
	}
	for (k = 0; k < FP8_TILE_K; k++) {
		e4_term ta = parse_e4m3fn(aK[k]);
		e4_term tb = parse_e4m3fn(bK[k]);
		int mag6;
		if (!ta.valid || !tb.valid) {
			return -1;
		}
		if (ta.zero || tb.zero) {
			prods[k].zero = true;
			prods[k].neg = false;
			prods[k].exp = 0;
			prods[k].sig = 0;
			continue;
		}
		mag6 = ta.mag3 * tb.mag3;
		prods[k].zero = false;
		prods[k].neg = ta.neg != tb.neg;
		prods[k].exp = ta.exp + tb.exp;
		prods[k].sig = ((uint64_t)mag6) << (FP8_FDA_FRAC - 6);
	}
	any = !unpacked.zero;
	e_max = unpacked.zero ? -1000000 : unpacked.exp;
	for (k = 0; k < FP8_TILE_K; k++) {
		if (prods[k].zero) {
			continue;
		}
		any = true;
		if (e_max == -1000000 || prods[k].exp > e_max) {
			e_max = prods[k].exp;
		}
	}
	if (!any) {
		*out = 0.f;
		return 0;
	}
	{
		int d;
		if (!unpacked.zero) {
			d = e_max - unpacked.exp;
			acc += unpacked.neg ? -(__int128)(d >= 63 ? 0 : unpacked.sig >> d) : (__int128)(d >= 63 ? 0 : unpacked.sig >> d);
		}
		for (k = 0; k < FP8_TILE_K; k++) {
			if (prods[k].zero) {
				continue;
			}
			d = e_max - prods[k].exp;
			{
				uint64_t aligned = d >= 63 ? 0 : prods[k].sig >> d;
				acc += prods[k].neg ? -(__int128)aligned : (__int128)aligned;
			}
		}
	}
	*out = normalize_rz_fp32(acc, e_max - FP8_FDA_FRAC);
	return 0;
}

int datum_job_fp8_expand_seed(const datum_header_v2_t *h, uint8_t seed[32])
{
	uint8_t ser[DATUM_HEADER_V2_SIZE];
	uint8_t tagged[16 + DATUM_HEADER_V2_SIZE];
	datum_pow_serialize_header(h, ser);
	memcpy(tagged, EXPAND_DOMAIN, 16);
	memcpy(tagged + 16, ser, DATUM_HEADER_V2_SIZE);
	return datum_pow_blake2b_32(tagged, sizeof(tagged), seed);
}

static int expand_ab(const datum_header_v2_t *h, uint8_t *a, uint8_t *b)
{
	uint8_t seed[32];
	uint8_t stream[2 * FP8_MATRIX_BYTES];
	uint8_t inn[40];
	int i;
	if (datum_job_fp8_expand_seed(h, seed) != 0) {
		return -1;
	}
	memset(inn, 0, sizeof(inn));
	memcpy(inn, seed, 32);
	for (i = 0; i < 2048; i++) {
		pk_u32le(inn, 32, (uint32_t)i);
		pk_u32le(inn, 36, 0);
		if (datum_pow_blake2b_64(inn, 40, stream + i * 64) != 0) {
			return -1;
		}
	}
	memcpy(a, stream, FP8_MATRIX_BYTES);
	memcpy(b, stream + FP8_MATRIX_BYTES, FP8_MATRIX_BYTES);
	for (i = 0; i < FP8_MATRIX_BYTES; i++) {
		if ((a[i] & 0x7f) == 0x7f) {
			a[i] = (uint8_t)((a[i] & 0x80) | 0x7e);
		}
		if ((b[i] & 0x7f) == 0x7f) {
			b[i] = (uint8_t)((b[i] & 0x80) | 0x7e);
		}
	}
	return 0;
}

static int tiled_mma(const uint8_t *a, const uint8_t *b, float *c)
{
	int kt, mt, nt, i, j, kk;
	uint8_t a_lane[FP8_TILE_K];
	uint8_t b_lane[FP8_TILE_K];
	memset(c, 0, FP8_MATRIX_BYTES * sizeof(float));
	for (kt = 0; kt < FP8_KT; kt++) {
		for (mt = 0; mt < FP8_MT; mt++) {
			for (nt = 0; nt < FP8_NT; nt++) {
				for (i = 0; i < FP8_TILE_M; i++) {
					for (j = 0; j < FP8_TILE_N; j++) {
						int row = mt * FP8_TILE_M + i;
						int col = nt * FP8_TILE_N + j;
						float out;
						for (kk = 0; kk < FP8_TILE_K; kk++) {
							int k = kt * FP8_TILE_K + kk;
							a_lane[kk] = a[row * FP8_DIM + k];
							b_lane[kk] = b[k * FP8_DIM + col];
						}
						if (qmma_k32(a_lane, b_lane, c[row * FP8_DIM + col], &out) != 0) {
							return -1;
						}
						c[row * FP8_DIM + col] = out;
					}
				}
			}
		}
	}
	return 0;
}

int datum_job_fp8_digest(const datum_header_v2_t *h, uint8_t out[32])
{
	uint8_t *a = malloc(FP8_MATRIX_BYTES);
	uint8_t *b = malloc(FP8_MATRIX_BYTES);
	float *c = malloc(FP8_MATRIX_BYTES * sizeof(float));
	uint8_t *packed = malloc(FP8_MATRIX_BYTES);
	uint8_t *tagged;
	int i;
	int rc = -1;
	if (!a || !b || !c || !packed) {
		goto done;
	}
	if (expand_ab(h, a, b) != 0) {
		goto done;
	}
	if (tiled_mma(a, b, c) != 0) {
		goto done;
	}
	for (i = 0; i < FP8_MATRIX_BYTES; i++) {
		packed[i] = quantize_e4m3fn(c[i]);
	}
	tagged = malloc(sizeof(OUT_DOMAIN) - 1 + FP8_MATRIX_BYTES);
	if (!tagged) {
		goto done;
	}
	memcpy(tagged, OUT_DOMAIN, sizeof(OUT_DOMAIN) - 1);
	memcpy(tagged + sizeof(OUT_DOMAIN) - 1, packed, FP8_MATRIX_BYTES);
	if (datum_pow_blake2b_32(tagged, sizeof(OUT_DOMAIN) - 1 + FP8_MATRIX_BYTES, out) == 0) {
		rc = 0;
	}
	free(tagged);
done:
	free(a);
	free(b);
	free(c);
	free(packed);
	return rc;
}
