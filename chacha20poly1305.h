#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define CHACHA20POLY1305_KEY_SIZE 32

bool chacha20poly1305_decrypt(uint8_t *dst, const uint8_t *src, const size_t src_len,
			      const uint8_t *ad, const size_t ad_len,
			      const uint8_t key[CHACHA20POLY1305_KEY_SIZE]);

