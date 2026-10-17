/*
 * Goldilocks Poseidon2. Port of federation-pool poseidon2.ts / node poseidon2.cpp. Not CONVOY.
 */

#include "datum_job.h"

#include <string.h>

#include "datum_utils.h"

#define P 0xffffffff00000001ULL
#define EPSILON 0xffffffffULL
#define WIDTH 12
#define RATE 8
#define OUTPUT 4
#define INTERNAL_ROUNDS 22

static const uint64_t INTERNAL_CONSTANTS[INTERNAL_ROUNDS] = {
	0x97f7798a784ad863ULL, 0xd1d2bf082f60d4f0ULL, 0x69a377a79f9ad206ULL, 0xa9d06906a3858e24ULL,
	0x295275001eede5b5ULL, 0x5874e441117bd746ULL, 0x8a084bbba8ed86ccULL, 0x3defd7645cde6425ULL,
	0x3998cfe6871cc137ULL, 0x3e52ef8bca48314aULL, 0x964a209f85dc9eccULL, 0x3fcc9ee82cc4577eULL,
	0x8e79b4a5d0096d6dULL, 0x8492362ad2392556ULL, 0xee72f470262574d6ULL, 0x1e0e18496da2444aULL,
	0x0f3a74bf215eaac6ULL, 0x1b061b76a1c0ded3ULL, 0x192c42d86803d7a6ULL, 0xf6d49ff997ae0260ULL,
	0x3ec372e7a0fa3786ULL, 0x5538cdf4f23445d3ULL,
};

static const uint64_t MATRIX_DIAG[WIDTH] = {
	0xc3b6c08e23ba9300ULL, 0xd84b5de94a324fb6ULL, 0x0d0c371c5b35b84fULL, 0x7964f570e7188037ULL,
	0x5daf18bbd996604bULL, 0x6743bc47b9595257ULL, 0x5528b9362c59bb70ULL, 0xac45e25b7127b68bULL,
	0xa2077d7dfbb606b5ULL, 0xf3faac6faee378aeULL, 0x0c6388b51545e883ULL, 0xd27dbb6944917b60ULL,
};

static const uint64_t INITIAL_EXTERNAL[4][WIDTH] = {
	{0xc002e770975b1607ULL, 0xbca51a8dfe14593aULL, 0x72938dfbe774f7f9ULL, 0xe4f2fe29e03234acULL,
	 0xd5e0ba2f541b6449ULL, 0xec33b868f3cc46c1ULL, 0x486dcb55419d475aULL, 0x6c1cb2a358cc24f1ULL,
	 0xe3f30d509a1436bbULL, 0xd9a64f068dca7c29ULL, 0xe59b3f57aabba1aeULL, 0x2a3dd4505b478fdcULL},
	{0xada1f8dc7676ed25ULL, 0x2711aa8b5509d516ULL, 0x4ae6acd0c9c92897ULL, 0x56eb3d6b5256d67aULL,
	 0x1f7a9d55923bf51eULL, 0x3600427d397a7f68ULL, 0xe5076df75b72c3d0ULL, 0xfcd59aa12c6090adULL,
	 0xcd895e8c68b57a9eULL, 0x41df7ef9d730ae3eULL, 0xee3e2b889abe977dULL, 0xd29bb7edbeb9c405ULL},
	{0x7d5c08eef608e382ULL, 0x89ae889caaf0802cULL, 0xb35a8e976d2af617ULL, 0xdb14234eafaf5173ULL,
	 0x78f04462d48b1c98ULL, 0x265293b0e47ce88aULL, 0x999a649b69b9d32fULL, 0x64b0a186698e01d3ULL,
	 0xee0b22d0dfae8bb8ULL, 0x4fd53e50ca04a7eeULL, 0x5762bfe181f25047ULL, 0xf51593e2beb5e3bdULL},
	{0x1e5e2b5760e32477ULL, 0x622462a1f9aaaeedULL, 0xaa284b3ecdb222aeULL, 0x63c8e72f542bf3fcULL,
	 0x3ba588cacb43b5e0ULL, 0x23eda6f3c99150ddULL, 0xaad3bea4baac9a5aULL, 0xe9da8d699b94184aULL,
	 0xcdb13f4cd93e024cULL, 0x902cbd0956f655e3ULL, 0x5b4e40ffc759532fULL, 0xde795c20a2357af7ULL},
};

static const uint64_t TERMINAL_EXTERNAL[4][WIDTH] = {
	{0x7b72c539e0ea4c6eULL, 0x144573dae2ce9976ULL, 0x802028b68f35fc88ULL, 0x6d36c5022c4fe7c2ULL,
	 0xa205d0ffa9b9def3ULL, 0xf6e7e38b1ea6ba2fULL, 0x34f7909ae5258d64ULL, 0xb0464d9d77b97fcaULL,
	 0x64ddb9d5de7e00a6ULL, 0x0ed0d75c27975d97ULL, 0x1cbb36f11127338bULL, 0x6673e505cfd0b6baULL},
	{0x605f902830872e01ULL, 0x3fd5eb927e95fe4fULL, 0xe81025b5a24c69cdULL, 0xf7d0ce75de23f74eULL,
	 0xf39942b6a8585089ULL, 0x6d808a08f7b71df6ULL, 0xf8806b6588f49a8bULL, 0x57df2d8c2a32107aULL,
	 0x16e7c2074d654a2dULL, 0x213de241fcf33835ULL, 0xb0f2b8905a0976f6ULL, 0xd8e3cf2bbd355417ULL},
	{0xe498691679d9330fULL, 0x763b45d2a3821b28ULL, 0x0908bf65eb0a1f0dULL, 0x7691eb2d194b24f4ULL,
	 0x0e43551233ae13b2ULL, 0x93c393dbfc2fe76fULL, 0x98f607485d48cdeaULL, 0xe3d95f30309819c0ULL,
	 0x1ef581a93eaf6acfULL, 0x0b24c1b7a030fca4ULL, 0x624370be5670b327ULL, 0x5f1e28615a11e486ULL},
	{0xfe04051f909e042bULL, 0x7257e5b147fd3803ULL, 0xe6ae134bb82f2e78ULL, 0x5711fd5cf4784511ULL,
	 0xf83a42660c08c0bcULL, 0x2cd8c96d9a3ce855ULL, 0x7d2ffb1bb0e17271ULL, 0x85ae1528caea3811ULL,
	 0x52a345d5c7adb0b8ULL, 0x504c4c51f3faee94ULL, 0xbce34a649cfccaf9ULL, 0xe0a3389266fb6dc9ULL},
};

static uint64_t from_raw(uint64_t v)
{
	return v >= P ? v - P : v;
}

static uint64_t fadd(uint64_t a, uint64_t b)
{
	uint64_t sum = a + b;
	bool over = sum < a;
	return from_raw(over ? (sum + EPSILON) : sum);
}

static uint64_t fmul(uint64_t a, uint64_t b)
{
	unsigned __int128 z = (unsigned __int128)a * (unsigned __int128)b;
	uint64_t xLo = (uint64_t)z;
	uint64_t xHi = (uint64_t)(z >> 64);
	uint64_t xHiHi = xHi >> 32;
	uint64_t xHiLo = xHi & EPSILON;
	bool borrow = xLo < xHiHi;
	uint64_t t0 = xLo - xHiHi;
	if (borrow) {
		t0 -= EPSILON;
	}
	uint64_t t1 = xHiLo * EPSILON;
	uint64_t t2 = t0 + t1;
	bool carry = t2 < t0;
	return from_raw(carry ? (t2 + EPSILON) : t2);
}

static uint64_t exp7(uint64_t x)
{
	uint64_t x2 = fmul(x, x);
	uint64_t x4 = fmul(x2, x2);
	return fmul(fmul(x4, x2), x);
}

static void apply_mat4(uint64_t *x, int o)
{
	uint64_t t01 = fadd(x[o], x[o + 1]);
	uint64_t t23 = fadd(x[o + 2], x[o + 3]);
	uint64_t t0123 = fadd(t01, t23);
	uint64_t t01123 = fadd(t0123, x[o + 1]);
	uint64_t t01233 = fadd(t0123, x[o + 3]);
	x[o + 3] = fadd(t01233, fadd(x[o], x[o]));
	x[o + 1] = fadd(t01123, fadd(x[o + 2], x[o + 2]));
	x[o] = fadd(t01123, t01);
	x[o + 2] = fadd(t01233, t23);
}

static void external_linear(uint64_t *state)
{
	int c, j, k, i;
	uint64_t sums[4];
	for (c = 0; c < WIDTH; c += 4) {
		apply_mat4(state, c);
	}
	sums[0] = sums[1] = sums[2] = sums[3] = 0;
	for (j = 0; j < WIDTH; j += 4) {
		for (k = 0; k < 4; k++) {
			sums[k] = fadd(sums[k], state[j + k]);
		}
	}
	for (i = 0; i < WIDTH; i++) {
		state[i] = fadd(state[i], sums[i % 4]);
	}
}

static void internal_linear(uint64_t *state)
{
	int i;
	uint64_t sum = 0;
	for (i = 0; i < WIDTH; i++) {
		sum = fadd(sum, state[i]);
	}
	for (i = 0; i < WIDTH; i++) {
		state[i] = fadd(sum, fmul(state[i], MATRIX_DIAG[i]));
	}
}

static void external_round(uint64_t *state, const uint64_t *rc)
{
	int i;
	for (i = 0; i < WIDTH; i++) {
		state[i] = exp7(fadd(state[i], rc[i]));
	}
	external_linear(state);
}

static void internal_round(uint64_t *state, uint64_t rc)
{
	state[0] = exp7(fadd(state[0], rc));
	internal_linear(state);
}

static void permute(uint64_t *state)
{
	int r;
	external_linear(state);
	for (r = 0; r < 4; r++) {
		external_round(state, INITIAL_EXTERNAL[r]);
	}
	for (r = 0; r < INTERNAL_ROUNDS; r++) {
		internal_round(state, INTERNAL_CONSTANTS[r]);
	}
	for (r = 0; r < 4; r++) {
		external_round(state, TERMINAL_EXTERNAL[r]);
	}
}

static void digest_to_bytes(const uint64_t *state, uint8_t out[32])
{
	int i;
	for (i = 0; i < OUTPUT; i++) {
		uint64_t v = state[i] >= P ? state[i] - P : state[i];
		pk_u32le(out, i * 8, (uint32_t)v);
		pk_u32le(out, i * 8 + 4, (uint32_t)(v >> 32));
	}
}

static void squeeze_twice(const uint8_t *input, size_t n, uint8_t out[64])
{
	uint64_t state[WIDTH];
	uint64_t buf[RATE];
	int buf_len = 0;
	size_t pos = 0;
	uint8_t last[4];
	size_t rem;
	int i;

	memset(state, 0, sizeof(state));
	memset(buf, 0, sizeof(buf));

	/* absorbFull / push as nested helpers would share this frame */
#define ABSORB_FULL() do { \
		for (i = 0; i < RATE; i++) { \
			state[i] = fadd(state[i], buf[i]); \
		} \
		permute(state); \
		memset(buf, 0, sizeof(buf)); \
		buf_len = 0; \
	} while (0)
#define PUSH(x) do { \
		buf[buf_len] = (x); \
		buf_len++; \
		if (buf_len == RATE) { \
			ABSORB_FULL(); \
		} \
	} while (0)

	while (pos + 4 <= n) {
		PUSH((uint64_t)upk_u32le(input, (int)pos));
		pos += 4;
	}
	memset(last, 0, 4);
	rem = n - pos;
	if (rem) {
		memcpy(last, input + pos, rem);
	}
	last[rem] = 1;
	PUSH((uint64_t)upk_u32le(last, 0));
	PUSH(1ULL);
	while (buf_len != 0) {
		PUSH(0ULL);
	}
	digest_to_bytes(state, out);
	permute(state);
	digest_to_bytes(state, out + 32);
#undef PUSH
#undef ABSORB_FULL
}

int datum_job_poseidon2_digest(const datum_header_v2_t *h, uint8_t out[32])
{
	static const char PRE_DOMAIN[] = "gfcn-poseidon2-pre-v1";
	datum_header_v2_t z = *h;
	uint8_t ser[DATUM_HEADER_V2_SIZE];
	uint8_t tagged[sizeof(PRE_DOMAIN) - 1 + DATUM_HEADER_V2_SIZE];
	uint8_t pre[32];
	uint8_t nonce[64];
	uint8_t job[96];
	uint8_t squeeze[64];
	int i;

	z.nNonce = 0;
	z.nonce2 = 0;
	z.nonce3 = 0;
	memset(z.extranonce, 0, 16);
	z.time_offset = 0;
	memset(z.mm_rhs, 0, 32);
	datum_pow_serialize_header(&z, ser);
	memcpy(tagged, PRE_DOMAIN, sizeof(PRE_DOMAIN) - 1);
	memcpy(tagged + sizeof(PRE_DOMAIN) - 1, ser, DATUM_HEADER_V2_SIZE);
	if (datum_pow_blake2b_32(tagged, sizeof(tagged), pre) != 0) {
		return -1;
	}

	memset(nonce, 0, sizeof(nonce));
	pk_u32le(nonce, 0, h->nNonce);
	pk_u32le(nonce, 4, h->nonce2);
	pk_u32le(nonce, 8, h->nonce3);
	memcpy(nonce + 12, h->extranonce, 16);
	pk_u32le(nonce, 28, h->time_offset);
	memcpy(nonce + 32, h->mm_rhs, 32);

	memcpy(job, pre, 32);
	memcpy(job + 32, nonce, 64);
	squeeze_twice(job, 96, squeeze);
	for (i = 0; i < 32; i++) {
		out[i] = squeeze[31 - i];
	}
	return 0;
}
