#define CURVE25519_KEY_SIZE 32

#include <stdint.h>

void curve25519(uint8_t out[CURVE25519_KEY_SIZE], const uint8_t scalar[CURVE25519_KEY_SIZE], const uint8_t point[CURVE25519_KEY_SIZE]);
