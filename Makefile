LDFLAGS := -lgcrypt -lpthread

all: wg_add

wg_add: wg_add.c wireguard.c wireguard.h key_tree.h key_tree.c

clean:
	rm *.o wg_add
