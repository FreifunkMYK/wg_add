#include "chacha20poly1305.h"
#include "byteorder.h"

#include <string.h>

#define CHACHA_KEY_SIZE 32
#define CHACHA_BLOCK_SIZE 64

#define CHACHA_STATE_WORDS (CHACHA_BLOCK_SIZE / sizeof(uint32_t))
#define CHACHA_KEY_WORDS (CHACHA_KEY_SIZE / sizeof(uint32_t))

#define POLY1305_BLOCK_SIZE 16
#define POLY1305_KEY_SIZE 32
#define POLY1305_DIGEST_SIZE 16

struct poly1305_key {
	union {
		uint32_t r[5];
		uint64_t r64[3];
	};
};

struct poly1305_core_key {
	struct poly1305_key key;
	struct poly1305_key precomputed_s;
};

struct poly1305_state {
	union {
		uint32_t h[5];
		uint64_t h64[3];
	};
};

struct poly1305_desc_ctx {
	/* partial buffer */
	uint8_t buf[POLY1305_BLOCK_SIZE];
	/* bytes used in partial buffer */
	unsigned int buflen;
	/* how many keys have been set in r[] */
	unsigned short rset;
	/* whether s[] has been set */
	bool sset;
	/* finalize key */
	uint32_t s[4];
	/* accumulator */
	struct poly1305_state h;
	/* key */
	union {
		struct poly1305_key opaque_r[11];
		struct poly1305_core_key core_r;
	};
};

static void chacha_load_key(uint32_t *k, const uint8_t *in)
{
	k[0] = le32_to_cpus(in);
	k[1] = le32_to_cpus(in + 4);
	k[2] = le32_to_cpus(in + 8);
	k[3] = le32_to_cpus(in + 12);
	k[4] = le32_to_cpus(in + 16);
	k[5] = le32_to_cpus(in + 20);
	k[6] = le32_to_cpus(in + 24);
	k[7] = le32_to_cpus(in + 28);
}

static inline void chacha_init_consts(uint32_t *state)
{
	state[0]  = 0x61707865; /* "expa" */
	state[1]  = 0x3320646e; /* "nd 3" */
	state[2]  = 0x79622d32; /* "2-by" */
	state[3]  = 0x6b206574; /* "te k" */
}

static inline void chacha_init(uint32_t *state, const uint32_t *key, const uint8_t *iv)
{
	chacha_init_consts(state);
	state[4]  = key[0];
	state[5]  = key[1];
	state[6]  = key[2];
	state[7]  = key[3];
	state[8]  = key[4];
	state[9]  = key[5];
	state[10] = key[6];
	state[11] = key[7];
	state[12] = le32_to_cpus(iv +  0);
	state[13] = le32_to_cpus(iv +  4);
	state[14] = le32_to_cpus(iv +  8);
	state[15] = le32_to_cpus(iv + 12);
}

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
	return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

static void chacha_permute(uint32_t *x, int nrounds)
{
	int i;

	for (i = 0; i < nrounds; i += 2) {
		x[0]  += x[4];    x[12] = rol32(x[12] ^ x[0],  16);
		x[1]  += x[5];    x[13] = rol32(x[13] ^ x[1],  16);
		x[2]  += x[6];    x[14] = rol32(x[14] ^ x[2],  16);
		x[3]  += x[7];    x[15] = rol32(x[15] ^ x[3],  16);

		x[8]  += x[12];   x[4]  = rol32(x[4]  ^ x[8],  12);
		x[9]  += x[13];   x[5]  = rol32(x[5]  ^ x[9],  12);
		x[10] += x[14];   x[6]  = rol32(x[6]  ^ x[10], 12);
		x[11] += x[15];   x[7]  = rol32(x[7]  ^ x[11], 12);

		x[0]  += x[4];    x[12] = rol32(x[12] ^ x[0],   8);
		x[1]  += x[5];    x[13] = rol32(x[13] ^ x[1],   8);
		x[2]  += x[6];    x[14] = rol32(x[14] ^ x[2],   8);
		x[3]  += x[7];    x[15] = rol32(x[15] ^ x[3],   8);

		x[8]  += x[12];   x[4]  = rol32(x[4]  ^ x[8],   7);
		x[9]  += x[13];   x[5]  = rol32(x[5]  ^ x[9],   7);
		x[10] += x[14];   x[6]  = rol32(x[6]  ^ x[10],  7);
		x[11] += x[15];   x[7]  = rol32(x[7]  ^ x[11],  7);

		x[0]  += x[5];    x[15] = rol32(x[15] ^ x[0],  16);
		x[1]  += x[6];    x[12] = rol32(x[12] ^ x[1],  16);
		x[2]  += x[7];    x[13] = rol32(x[13] ^ x[2],  16);
		x[3]  += x[4];    x[14] = rol32(x[14] ^ x[3],  16);

		x[10] += x[15];   x[5]  = rol32(x[5]  ^ x[10], 12);
		x[11] += x[12];   x[6]  = rol32(x[6]  ^ x[11], 12);
		x[8]  += x[13];   x[7]  = rol32(x[7]  ^ x[8],  12);
		x[9]  += x[14];   x[4]  = rol32(x[4]  ^ x[9],  12);

		x[0]  += x[5];    x[15] = rol32(x[15] ^ x[0],   8);
		x[1]  += x[6];    x[12] = rol32(x[12] ^ x[1],   8);
		x[2]  += x[7];    x[13] = rol32(x[13] ^ x[2],   8);
		x[3]  += x[4];    x[14] = rol32(x[14] ^ x[3],   8);

		x[10] += x[15];   x[5]  = rol32(x[5]  ^ x[10],  7);
		x[11] += x[12];   x[6]  = rol32(x[6]  ^ x[11],  7);
		x[8]  += x[13];   x[7]  = rol32(x[7]  ^ x[8],   7);
		x[9]  += x[14];   x[4]  = rol32(x[4]  ^ x[9],   7);
	}
}

void chacha_block(uint32_t *state, uint8_t *stream, int nrounds)
{
	uint32_t x[16];
	int i;

	memcpy(x, state, 64);

	chacha_permute(x, nrounds);

	for (i = 0; i < 16; i++)
		*(uint32_t *)(&stream[i * sizeof(uint32_t)])=le32_to_cpu(x[i] + state[i]);

	state[12]++;
}

void __crypto_xor(uint8_t *dst, const uint8_t *src1, const uint8_t *src2, unsigned int len)
{
	while (len >= 8) {
		*(uint64_t *)dst = *(uint64_t *)src1 ^  *(uint64_t *)src2;
		dst += 8;
		src1 += 8;
		src2 += 8;
		len -= 8;
	}

	while (len >= 4) {
		*(uint32_t *)dst = *(uint32_t *)src1 ^ *(uint32_t *)src2;
		dst += 4;
		src1 += 4;
		src2 += 4;
		len -= 4;
	}

	while (len >= 2) {
		*(uint16_t *)dst = *(uint16_t *)src1 ^ *(uint16_t *)src2;
		dst += 2;
		src1 += 2;
		src2 += 2;
		len -= 2;
	}

	while (len--)
		*dst++ = *src1++ ^ *src2++;
}

static inline void crypto_xor_cpy(uint8_t *dst, const uint8_t *src1, const uint8_t *src2,
				  unsigned int size)
{
	if ((size % sizeof(unsigned long)) == 0) {
		unsigned long *d = (unsigned long *)dst;
		unsigned long *s1 = (unsigned long *)src1;
		unsigned long *s2 = (unsigned long *)src2;

		while (size > 0) {
			*d++ = *s1++ ^ *s2++;
			size -= sizeof(unsigned long);
		}
	} else {
		__crypto_xor(dst, src1, src2, size);
	}
}

void chacha_crypt(uint32_t *state, uint8_t *dst, const uint8_t *src,
			  unsigned int bytes, int nrounds)
{
	uint8_t stream[CHACHA_BLOCK_SIZE];

	while (bytes >= CHACHA_BLOCK_SIZE) {
		chacha_block(state, stream, nrounds);
		crypto_xor_cpy(dst, src, stream, CHACHA_BLOCK_SIZE);
		bytes -= CHACHA_BLOCK_SIZE;
		dst += CHACHA_BLOCK_SIZE;
		src += CHACHA_BLOCK_SIZE;
	}
	if (bytes) {
		chacha_block(state, stream, nrounds);
		crypto_xor_cpy(dst, src, stream, bytes);
	}
}

static inline void chacha20_crypt(uint32_t *state, uint8_t *dst, const uint8_t *src,
				  unsigned int bytes)
{
	chacha_crypt(state, dst, src, bytes, 20);
}

void poly1305_core_setkey(struct poly1305_core_key *key,
			  const uint8_t raw_key[POLY1305_BLOCK_SIZE])
{
	/* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
	key->key.r[0] = (le32_to_cpus(&raw_key[0])) & 0x3ffffff;
	key->key.r[1] = (le32_to_cpus(&raw_key[3]) >> 2) & 0x3ffff03;
	key->key.r[2] = (le32_to_cpus(&raw_key[6]) >> 4) & 0x3ffc0ff;
	key->key.r[3] = (le32_to_cpus(&raw_key[9]) >> 6) & 0x3f03fff;
	key->key.r[4] = (le32_to_cpus(&raw_key[12]) >> 8) & 0x00fffff;

	/* s = 5*r */
	key->precomputed_s.r[0] = key->key.r[1] * 5;
	key->precomputed_s.r[1] = key->key.r[2] * 5;
	key->precomputed_s.r[2] = key->key.r[3] * 5;
	key->precomputed_s.r[3] = key->key.r[4] * 5;
}

static inline void poly1305_core_init(struct poly1305_state *state)
{
	*state = (struct poly1305_state){};
}

void poly1305_init(struct poly1305_desc_ctx *desc,
			   const uint8_t key[POLY1305_KEY_SIZE])
{
	poly1305_core_setkey(&desc->core_r, key);
	desc->s[0] = le32_to_cpus(key + 16);
	desc->s[1] = le32_to_cpus(key + 20);
	desc->s[2] = le32_to_cpus(key + 24);
	desc->s[3] = le32_to_cpus(key + 28);
	poly1305_core_init(&desc->h);
	desc->buflen = 0;
	desc->sset = true;
	desc->rset = 2;
}

void poly1305_core_blocks(struct poly1305_state *state,
			  const struct poly1305_core_key *key, const void *src,
			  unsigned int nblocks, uint32_t hibit)
{
	const uint8_t *input = src;
	uint32_t r0, r1, r2, r3, r4;
	uint32_t s1, s2, s3, s4;
	uint32_t h0, h1, h2, h3, h4;
	uint64_t d0, d1, d2, d3, d4;
	uint32_t c;

	if (!nblocks)
		return;

	hibit <<= 24;

	r0 = key->key.r[0];
	r1 = key->key.r[1];
	r2 = key->key.r[2];
	r3 = key->key.r[3];
	r4 = key->key.r[4];

	s1 = key->precomputed_s.r[0];
	s2 = key->precomputed_s.r[1];
	s3 = key->precomputed_s.r[2];
	s4 = key->precomputed_s.r[3];

	h0 = state->h[0];
	h1 = state->h[1];
	h2 = state->h[2];
	h3 = state->h[3];
	h4 = state->h[4];

	do {
		/* h += m[i] */
		h0 += (le32_to_cpus(&input[0])) & 0x3ffffff;
		h1 += (le32_to_cpus(&input[3]) >> 2) & 0x3ffffff;
		h2 += (le32_to_cpus(&input[6]) >> 4) & 0x3ffffff;
		h3 += (le32_to_cpus(&input[9]) >> 6) & 0x3ffffff;
		h4 += (le32_to_cpus(&input[12]) >> 8) | hibit;

		/* h *= r */
		d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) +
		     ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) +
		     ((uint64_t)h4 * s1);
		d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) +
		     ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) +
		     ((uint64_t)h4 * s2);
		d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) +
		     ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) +
		     ((uint64_t)h4 * s3);
		d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) +
		     ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) +
		     ((uint64_t)h4 * s4);
		d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) +
		     ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) +
		     ((uint64_t)h4 * r0);

		/* (partial) h %= p */
		c = (uint32_t)(d0 >> 26);
		h0 = (uint32_t)d0 & 0x3ffffff;
		d1 += c;
		c = (uint32_t)(d1 >> 26);
		h1 = (uint32_t)d1 & 0x3ffffff;
		d2 += c;
		c = (uint32_t)(d2 >> 26);
		h2 = (uint32_t)d2 & 0x3ffffff;
		d3 += c;
		c = (uint32_t)(d3 >> 26);
		h3 = (uint32_t)d3 & 0x3ffffff;
		d4 += c;
		c = (uint32_t)(d4 >> 26);
		h4 = (uint32_t)d4 & 0x3ffffff;
		h0 += c * 5;
		c = (h0 >> 26);
		h0 = h0 & 0x3ffffff;
		h1 += c;

		input += POLY1305_BLOCK_SIZE;
	} while (--nblocks);

	state->h[0] = h0;
	state->h[1] = h1;
	state->h[2] = h2;
	state->h[3] = h3;
	state->h[4] = h4;
}

void poly1305_update(struct poly1305_desc_ctx *desc, const uint8_t *src,
			     unsigned int nbytes)
{
	unsigned int bytes;

	if (desc->buflen) {
		bytes = (nbytes < (POLY1305_BLOCK_SIZE - desc->buflen)) ? nbytes : (POLY1305_BLOCK_SIZE - desc->buflen);
		memcpy(desc->buf + desc->buflen, src, bytes);
		src += bytes;
		nbytes -= bytes;
		desc->buflen += bytes;

		if (desc->buflen == POLY1305_BLOCK_SIZE) {
			poly1305_core_blocks(&desc->h, &desc->core_r, desc->buf,
					     1, 1);
			desc->buflen = 0;
		}
	}

	if (nbytes >= POLY1305_BLOCK_SIZE) {
		poly1305_core_blocks(&desc->h, &desc->core_r, src,
				     nbytes / POLY1305_BLOCK_SIZE, 1);
		src += nbytes - (nbytes % POLY1305_BLOCK_SIZE);
		nbytes %= POLY1305_BLOCK_SIZE;
	}

	if (nbytes) {
		desc->buflen = nbytes;
		memcpy(desc->buf, src, nbytes);
	}
}

void poly1305_core_emit(const struct poly1305_state *state, const uint32_t nonce[4],
			void *dst)
{
	uint8_t *mac = dst;
	uint32_t h0, h1, h2, h3, h4, c;
	uint32_t g0, g1, g2, g3, g4;
	uint64_t f;
	uint32_t mask;

	/* fully carry h */
	h0 = state->h[0];
	h1 = state->h[1];
	h2 = state->h[2];
	h3 = state->h[3];
	h4 = state->h[4];

	c = h1 >> 26;
	h1 = h1 & 0x3ffffff;
	h2 += c;
	c = h2 >> 26;
	h2 = h2 & 0x3ffffff;
	h3 += c;
	c = h3 >> 26;
	h3 = h3 & 0x3ffffff;
	h4 += c;
	c = h4 >> 26;
	h4 = h4 & 0x3ffffff;
	h0 += c * 5;
	c = h0 >> 26;
	h0 = h0 & 0x3ffffff;
	h1 += c;

	/* compute h + -p */
	g0 = h0 + 5;
	c = g0 >> 26;
	g0 &= 0x3ffffff;
	g1 = h1 + c;
	c = g1 >> 26;
	g1 &= 0x3ffffff;
	g2 = h2 + c;
	c = g2 >> 26;
	g2 &= 0x3ffffff;
	g3 = h3 + c;
	c = g3 >> 26;
	g3 &= 0x3ffffff;
	g4 = h4 + c - (1UL << 26);

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> ((sizeof(uint32_t) * 8) - 1)) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;

	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	h0 = ((h0) | (h1 << 26)) & 0xffffffff;
	h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
	h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
	h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;

	if (nonce) {
		/* mac = (h + nonce) % (2^128) */
		f = (uint64_t)h0 + nonce[0];
		h0 = (uint32_t)f;
		f = (uint64_t)h1 + nonce[1] + (f >> 32);
		h1 = (uint32_t)f;
		f = (uint64_t)h2 + nonce[2] + (f >> 32);
		h2 = (uint32_t)f;
		f = (uint64_t)h3 + nonce[3] + (f >> 32);
		h3 = (uint32_t)f;
	}

	*(uint32_t *)&mac[0] = le32_to_cpu(h0);
	*(uint32_t *)&mac[4] = le32_to_cpu(h1);
	*(uint32_t *)&mac[8] = le32_to_cpu(h2);
	*(uint32_t *)&mac[12] = le32_to_cpu(h3);
}

void poly1305_final(struct poly1305_desc_ctx *desc, uint8_t *dst)
{
	if (desc->buflen) {
		desc->buf[desc->buflen++] = 1;
		memset(desc->buf + desc->buflen, 0,
		       POLY1305_BLOCK_SIZE - desc->buflen);
		poly1305_core_blocks(&desc->h, &desc->core_r, desc->buf, 1, 0);
	}

	poly1305_core_emit(&desc->h, desc->s, dst);
	*desc = (struct poly1305_desc_ctx){};
}

static bool __chacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, const size_t src_len,
			   const uint8_t *ad, const size_t ad_len, uint32_t *chacha_state)
{
	const uint8_t pad0[32] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	struct poly1305_desc_ctx poly1305_state;
	size_t dst_len;
	int ret;
	union {
		uint8_t block0[POLY1305_KEY_SIZE];
		uint8_t mac[POLY1305_DIGEST_SIZE];
		uint64_t lens[2];
	} b;

	if (src_len < POLY1305_DIGEST_SIZE)
		return false;

	chacha20_crypt(chacha_state, b.block0, pad0, sizeof(b.block0));
	poly1305_init(&poly1305_state, b.block0);

	poly1305_update(&poly1305_state, ad, ad_len);
	if (ad_len & 0xf)
		poly1305_update(&poly1305_state, pad0, 0x10 - (ad_len & 0xf));

	dst_len = src_len - POLY1305_DIGEST_SIZE;
	poly1305_update(&poly1305_state, src, dst_len);
	if (dst_len & 0xf)
		poly1305_update(&poly1305_state, pad0, 0x10 - (dst_len & 0xf));

	b.lens[0] = le64_to_cpus((uint64_t *)&ad_len);
	b.lens[1] = le64_to_cpus((uint64_t *)&dst_len);
	poly1305_update(&poly1305_state, (uint8_t *)b.lens, sizeof(b.lens));

	poly1305_final(&poly1305_state, b.mac);

	ret = memcmp(b.mac, src + dst_len, POLY1305_DIGEST_SIZE);
	if (!ret)
		chacha20_crypt(chacha_state, dst, src, dst_len);

	memset(&b, 0, sizeof(b));

	return !ret;
}

bool chacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, const size_t src_len,
			      const uint8_t *ad, const size_t ad_len,
			      const uint8_t key[CHACHA20POLY1305_KEY_SIZE])
{
	uint32_t chacha_state[CHACHA_STATE_WORDS];
	uint32_t k[CHACHA_KEY_WORDS];
	uint64_t iv[2];
	bool ret;

	chacha_load_key(k, key);

	iv[0] = 0;
	iv[1] = 0;

	chacha_init(chacha_state, k, (uint8_t *)iv);
	ret = __chacha20poly1305_decrypt(dst, src, src_len, ad, ad_len,
					 chacha_state);

	memset(chacha_state, 0, sizeof(chacha_state));
	memset(iv, 0, sizeof(iv));
	memset(k, 0, sizeof(k));
	return ret;
}
