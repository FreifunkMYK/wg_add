/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTO_MD5_H
#define _CRYPTO_MD5_H

#define MD5_DIGEST_SIZE		16
#define MD5_HMAC_BLOCK_SIZE	64
#define MD5_BLOCK_WORDS		16
#define MD5_HASH_WORDS		4

#define MD5_H0	0x67452301UL
#define MD5_H1	0xefcdab89UL
#define MD5_H2	0x98badcfeUL
#define MD5_H3	0x10325476UL

#include <stdint.h>

extern const uint8_t md5_zero_message_hash[MD5_DIGEST_SIZE];

struct md5_state {
	uint32_t hash[MD5_HASH_WORDS];
	uint32_t block[MD5_BLOCK_WORDS];
	uint64_t byte_count;
};

int md5_init(struct md5_state *mctx);
int md5_update(struct md5_state *mctx, const uint8_t *data, unsigned int len);
int md5_final(struct md5_state *mctx, uint8_t *out);

#endif
