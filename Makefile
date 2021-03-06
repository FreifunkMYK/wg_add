LDFLAGS := -lpthread

all: wg_add

wg_add: wg_add.c wireguard.c wireguard.h key_tree.h key_tree.c blake2s.h blake2s.c blake2s-generic.c curve25519.c curve25519.h byteorder.h md5.c md5.h chacha20poly1305.c chacha20poly1305.h

clean:
	rm *.o wg_add
