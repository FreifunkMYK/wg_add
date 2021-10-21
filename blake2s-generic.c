// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is an implementation of the BLAKE2s hash and PRF functions.
 *
 * Information: https://blake2.net/
 *
 */

#include "blake2s.h"

uint32_t ror32(uint32_t word, unsigned int shift)
{
	return (word >> (shift & 31)) | (word << ((-shift) & 31));
}

static const uint8_t blake2s_sigma[10][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

static inline void blake2s_increment_counter(struct blake2s_state *state,
					     const uint32_t inc)
{
	state->t[0] += inc;
	state->t[1] += (state->t[0] < inc);
}

void blake2s_compress_generic(struct blake2s_state *state,const uint8_t *block,
			      size_t nblocks, const uint32_t inc)
{
	uint32_t m[16];
	uint32_t v[16];
	int i;

	if(nblocks > 1 && inc != BLAKE2S_BLOCK_SIZE)
		printf("blake2s_compress_generic: conditions not met\n");

	while (nblocks > 0) {
		blake2s_increment_counter(state, inc);
		memcpy(m, block, BLAKE2S_BLOCK_SIZE);
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define swap32(x) ((uint32_t)( \
			(((uint32_t)(x) & 0x000000ffu) << 24) | \
			(((uint32_t)(x) & 0x0000ff00u) <<  8) | \
			(((uint32_t)(x) & 0x00ff0000u) >>  8) | \
			(((uint32_t)(x) & 0xff000000u) >> 24)))
	state->h[0] = swap32(state->h[0]);
	state->h[1] = swap32(state->h[1]);
	state->h[2] = swap32(state->h[2]);
	state->h[3] = swap32(state->h[3]);
	state->h[4] = swap32(state->h[4]);
	state->h[5] = swap32(state->h[5]);
	state->h[6] = swap32(state->h[6]);
	state->h[7] = swap32(state->h[7]);
#undef swap32
#endif
		memcpy(v, state->h, 32);
		v[ 8] = BLAKE2S_IV0;
		v[ 9] = BLAKE2S_IV1;
		v[10] = BLAKE2S_IV2;
		v[11] = BLAKE2S_IV3;
		v[12] = BLAKE2S_IV4 ^ state->t[0];
		v[13] = BLAKE2S_IV5 ^ state->t[1];
		v[14] = BLAKE2S_IV6 ^ state->f[0];
		v[15] = BLAKE2S_IV7 ^ state->f[1];

#define G(r, i, a, b, c, d) do { \
	a += b + m[blake2s_sigma[r][2 * i + 0]]; \
	d = ror32(d ^ a, 16); \
	c += d; \
	b = ror32(b ^ c, 12); \
	a += b + m[blake2s_sigma[r][2 * i + 1]]; \
	d = ror32(d ^ a, 8); \
	c += d; \
	b = ror32(b ^ c, 7); \
} while (0)

#define ROUND(r) do { \
	G(r, 0, v[0], v[ 4], v[ 8], v[12]); \
	G(r, 1, v[1], v[ 5], v[ 9], v[13]); \
	G(r, 2, v[2], v[ 6], v[10], v[14]); \
	G(r, 3, v[3], v[ 7], v[11], v[15]); \
	G(r, 4, v[0], v[ 5], v[10], v[15]); \
	G(r, 5, v[1], v[ 6], v[11], v[12]); \
	G(r, 6, v[2], v[ 7], v[ 8], v[13]); \
	G(r, 7, v[3], v[ 4], v[ 9], v[14]); \
} while (0)
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

#undef G
#undef ROUND

		for (i = 0; i < 8; ++i)
			state->h[i] ^= v[i] ^ v[i + 8];

		block += BLAKE2S_BLOCK_SIZE;
		--nblocks;
	}
}
