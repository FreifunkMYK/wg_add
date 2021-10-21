LDFLAGS := -lgcrypt -lpthread

all: wg_add

wg_add: wg_add.c wireguard.c wireguard.h key_tree.h key_tree.c blake2s.h blake2s.c blake2s-generic.c curve25519.c curve25519.h

clean:
	rm *.o wg_add
