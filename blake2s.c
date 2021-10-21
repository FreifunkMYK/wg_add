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

void blake2s_compress_generic(struct blake2s_state *state,const uint8_t *block, size_t nblocks, const uint32_t inc);

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

void blake2s_update(struct blake2s_state *state, const uint8_t *in, size_t inlen)
{
	const size_t fill = BLAKE2S_BLOCK_SIZE - state->buflen;

	if (!inlen)
		return;
	if (inlen > fill) {
		memcpy(state->buf + state->buflen, in, fill);
		blake2s_compress_generic(state, state->buf, 1, BLAKE2S_BLOCK_SIZE);
		state->buflen = 0;
		in += fill;
		inlen -= fill;
	}
	if (inlen > BLAKE2S_BLOCK_SIZE) {
		const size_t nblocks = DIV_ROUND_UP(inlen, BLAKE2S_BLOCK_SIZE);
		/* Hash one less (full) block than strictly possible */
		blake2s_compress_generic(state, in, nblocks - 1, BLAKE2S_BLOCK_SIZE);
		in += BLAKE2S_BLOCK_SIZE * (nblocks - 1);
		inlen -= BLAKE2S_BLOCK_SIZE * (nblocks - 1);
	}
	memcpy(state->buf + state->buflen, in, inlen);
	state->buflen += inlen;
}

static inline void blake2s_set_lastblock(struct blake2s_state *state)
{
	state->f[0] = -1;
}

void blake2s_final(struct blake2s_state *state, uint8_t *out)
{
	if(!out)
        printf("blake2s_final: conditions not met\n");
	blake2s_set_lastblock(state);
	memset(state->buf + state->buflen, 0,
	       BLAKE2S_BLOCK_SIZE - state->buflen); /* Padding */
	blake2s_compress_generic(state, state->buf, 1, state->buflen);
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
	memcpy(out, state->h, state->outlen);
	memset(state, 0, sizeof(*state));
}

void blake2s256_hmac(uint8_t *out, const uint8_t *in, const uint8_t *key, const size_t inlen,
		     const size_t keylen)
{
	struct blake2s_state state;
	uint8_t x_key[BLAKE2S_BLOCK_SIZE] = { 0 };
	uint8_t i_hash[BLAKE2S_HASH_SIZE];
	int i;

	if (keylen > BLAKE2S_BLOCK_SIZE) {
		blake2s_init(&state, BLAKE2S_HASH_SIZE);
		blake2s_update(&state, key, keylen);
		blake2s_final(&state, x_key);
	} else
		memcpy(x_key, key, keylen);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x36;

	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	blake2s_update(&state, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&state, in, inlen);
	blake2s_final(&state, i_hash);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x5c ^ 0x36;

	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	blake2s_update(&state, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&state, i_hash, BLAKE2S_HASH_SIZE);
	blake2s_final(&state, i_hash);

	memcpy(out, i_hash, BLAKE2S_HASH_SIZE);
	memset(x_key, 0, BLAKE2S_BLOCK_SIZE);
	memset(i_hash, 0, BLAKE2S_HASH_SIZE);
}
