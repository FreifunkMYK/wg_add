#include <stdint.h>

static inline uint64_t le64_to_cpus(const void *buf)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return  (((uint64_t)(buf) & 0xff00000000000000ull) >> 56) | \
			(((uint64_t)(buf) & 0x00ff000000000000ull) >> 40) | \
			(((uint64_t)(buf) & 0x0000ff0000000000ull) >> 24) | \
			(((uint64_t)(buf) & 0x000000ff00000000ull) >>  8) | \
			(((uint64_t)(buf) & 0x00000000ff000000ull) <<  8) | \
			(((uint64_t)(buf) & 0x0000000000ff0000ull) << 24) | \
			(((uint64_t)(buf) & 0x000000000000ff00ull) << 40) | \
			(((uint64_t)(buf) & 0x00000000000000ffull) << 56);
#else
    return *(uint64_t *)(buf);
#endif
};

static inline uint32_t le32_to_cpus(const void *buf)
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return (((uint32_t)(buf) & 0x000000ffu) << 24) | \
			(((uint32_t)(buf) & 0x0000ff00u) <<  8) | \
			(((uint32_t)(buf) & 0x00ff0000u) >>  8) | \
			(((uint32_t)(buf) & 0xff000000u) >> 24);
#else
    return *(uint32_t *)(buf);
#endif
};

static inline void le32_to_cpu_array(uint32_t *buf, unsigned int words)
{
    while(words--) {
        le32_to_cpus(buf);
        buf++;
    }
}

static inline void cpu_to_le32_array(uint32_t *buf, unsigned int words)
{
    while(words--) {
        le32_to_cpus(buf);
        buf++;
    }
}
