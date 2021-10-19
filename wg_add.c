#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <poll.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>

#include <gcrypt.h>

#include "wireguard.h"
#include "key_tree.h"

#define timediff(a, b, result)					\
	do {										\
		result.tv_sec = a.tv_sec - b.tv_sec;	\
		result.tv_nsec = a.tv_nsec - b.tv_nsec;	\
		if (result.tv_nsec < 0) {				\
			--result.tv_sec;					\
			result.tv_nsec += 1000000000L;		\
		}										\
	} while (0)

wg_key server_priv_key;
wg_key server_pub_key;
wg_key mac1_key;
char *wg_device_name;
char *vx_device_name;

wg_key hash_of_construction;
wg_key hash_of_c_identifier;

bool run = true;

struct key_tree * key_tree = NULL;

void signal_handler(int sig) {
	if( sig != SIGTERM )
		return;
	run = false;
}

void printf_key(const char * name, wg_key key) {
	wg_key_b64_string key_str;
	wg_key_to_base64(key_str, key);
	printf("%s: %s\n", name, key_str);
}

void wg_key_to_ipv6(char *ipv6, const wg_key key) {
	wg_key_b64_string key_str;
	char md5[16] = {0};

	wg_key_to_base64(key_str, key);
	{
		gcry_md_hd_t hd;
		if (gcry_md_open(&hd, GCRY_MD_MD5, 0)) {
			return;
		}
		gcry_md_write(hd, key_str, sizeof(wg_key_b64_string)-1);
		gcry_md_putc(hd, '\n');
		memcpy(md5, gcry_md_read(hd, 0), gcry_md_get_algo_dlen(GCRY_MD_MD5));
		gcry_md_close(hd);
	}
	sprintf(ipv6, "fe80::%02x:%02xff:fe%02x:%02x%02x", (uint8_t)md5[0], (uint8_t)md5[1], (uint8_t)md5[2], (uint8_t)md5[3], (uint8_t)md5[4]);
}

void add_key_to_wg(wg_key key) {
	if(key_in_tree(key_tree, key))
		return;
	printf_key("adding key", key);

	char ipv6[40] = {0};
	wg_key_to_ipv6(ipv6, key);

	// wg
	{
		wg_device device = {0};
		wg_peer peer = {0};
		wg_allowedip allowed_ip = {0};
		strncpy(device.name, wg_device_name, IFNAMSIZ -  1);
		device.name[IFNAMSIZ-1] = '\0';
		device.first_peer = &peer;
		device.last_peer = &peer;

		peer.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS | WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
		memcpy(peer.public_key, key, 32);
		peer.persistent_keepalive_interval = 15;
		peer.first_allowedip = &allowed_ip;
		peer.last_allowedip = &allowed_ip;

		allowed_ip.family = AF_INET6;
		inet_pton(AF_INET6, ipv6, &(allowed_ip.ip6));
		allowed_ip.cidr = 128;

		if(wg_set_device(&device) < 0) {
			perror("Unable to set device");
			return;
		}
	}
	// route
	{
		char cmd[100];
		sprintf(cmd, "ip route add %s/128 dev %s", ipv6, wg_device_name);
		system(cmd);
	}
	// bridge fdb
	{
		char cmd[100];
		sprintf(cmd, "bridge fdb append 00:00:00:00:00:00 dev %s dst %s via %s", vx_device_name, ipv6, wg_device_name);
		system(cmd);
	}

	add_key_to_tree(key_tree, key);
}

void remove_key_from_wg(wg_key key) {
	if(!key_in_tree(key_tree, key))
		return;
	printf_key("removing key", key);

	char ipv6[40] = {0};
	wg_key_to_ipv6(ipv6, key);

	// wg
	{
		wg_device device = {0};
		wg_peer peer = {0};
		wg_allowedip allowed_ip = {0};
		strncpy(device.name, wg_device_name, IFNAMSIZ -  1);
		device.name[IFNAMSIZ-1] = '\0';
		device.first_peer = &peer;
		device.last_peer = &peer;

		peer.flags = WGPEER_HAS_PUBLIC_KEY | WGPEER_REMOVE_ME;
		memcpy(peer.public_key, key, 32);

		if(wg_set_device(&device) < 0) {
			perror("Unable to set device");
			return;
		}
	}
	// route
	{
		char cmd[100];
		sprintf(cmd, "ip route del %s/128 dev %s", ipv6, wg_device_name);
		system(cmd);
	}
	// bridge fdb
	{
		char cmd[100];
		sprintf(cmd, "bridge fdb del 00:00:00:00:00:00 dev %s dst %s via %s", vx_device_name, ipv6, wg_device_name);
		system(cmd);
	}

	remove_key_from_tree(key_tree, key);
}

void * flush_stale_peers(void *) {
	struct timespec time_to_sleep = { .tv_sec = 1, .tv_nsec = 0 };
	struct timespec last_run;
	struct timespec diff;
	clock_gettime(CLOCK_MONOTONIC, &last_run);
	while(run)
	{
		struct timespec now;
		do
		{
			nanosleep(&time_to_sleep, NULL);
			clock_gettime(CLOCK_MONOTONIC, &now);
			timediff(now, last_run, diff);
		} while( run &&  diff.tv_sec < 300 );

		clock_gettime(CLOCK_MONOTONIC, &last_run);

		printf("flushing stale peers...\n");
		wg_device *device;
		if(wg_get_device(&device, wg_device_name) < 0) {
			printf("Unable to get wg device\n");
			wg_free_device(device);
			continue;
		}

		clock_gettime(CLOCK_REALTIME, &now);

		wg_peer *peer;
		wg_for_each_peer(device, peer) {
			if(!key_in_tree(key_tree, peer->public_key))
				add_key_to_tree(key_tree, peer->public_key);

			timediff(now, peer->last_handshake_time, diff);
			if(diff.tv_sec > (3 * 60 * 60))
				remove_key_from_wg(peer->public_key);
		}

		wg_free_device(device);
	}
}

bool wg_mix_hash(wg_key *h, const void * data, size_t data_len) {
	gcry_md_hd_t hd;
	if (gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0)) {
		return false;
	}
	gcry_md_write(hd, h, sizeof(wg_key));
	gcry_md_write(hd, data, data_len);
	memcpy(h, gcry_md_read(hd, 0), sizeof(wg_key));
	gcry_md_close(hd);
	return true;
}

static bool wg_kdf(const wg_key *key, const u_char *input, size_t input_len, int n, wg_key *out)
{
	u_char          prk[32];    /* Blake2s_256 hash output. */
	gcry_error_t    err;
	{
		gcry_md_hd_t hmac_handle;
		err = gcry_md_open(&hmac_handle, GCRY_MD_BLAKE2S_256, GCRY_MD_FLAG_HMAC);
		if( err ) {
			return false;
		}
		err = gcry_md_setkey(hmac_handle, key, 32);
		if( err ) {
			gcry_md_close(hmac_handle);
			return false;
		}
		gcry_md_write(hmac_handle, input, input_len);
		memcpy(prk, gcry_md_read(hmac_handle, 0), gcry_md_get_algo_dlen(GCRY_MD_BLAKE2S_256));
		gcry_md_close(hmac_handle);
	}
	{
		u_char          lastoutput[32];
		gcry_md_hd_t    h;

		err = gcry_md_open(&h, GCRY_MD_BLAKE2S_256, GCRY_MD_FLAG_HMAC);
		if( err ) {
			return false;
		}
		for (size_t offset = 0; offset < n; offset++) {
			gcry_md_reset(h);
			gcry_md_setkey(h, prk, 32);
			if (offset > 0) {
				gcry_md_write(h, lastoutput, 32);
			}
			gcry_md_putc(h, (u_char) (offset + 1));

			memcpy(lastoutput, gcry_md_read(h, GCRY_MD_BLAKE2S_256), 32);
			memcpy(out + offset, lastoutput, 32);
		}

		gcry_md_close(h);
	}
	return true;
}

static inline void
copy_and_reverse(unsigned char *dest, const unsigned char *src, size_t n)
{
	for (size_t i = 0; i < n; i++) {
	dest[n - 1 - i] = src[i];
	}
}

static int
x25519_mpi(unsigned char *q, const unsigned char *n, gcry_mpi_t mpi_p)
{
    unsigned char priv_be[32];
    unsigned char result_be[32];
    size_t result_len = 0;
    gcry_mpi_t mpi = NULL;
    gcry_ctx_t ctx = NULL;
    gcry_mpi_point_t P = NULL;
    gcry_mpi_point_t Q = NULL;
    int r = -1;

    /* Default to infinity (all zeroes). */
    memset(q, 0, 32);

    /* Keys are in little-endian, but gcry_mpi_scan expects big endian. Convert
     * keys and ensure that the result is a valid Curve25519 secret scalar. */
    copy_and_reverse(priv_be, n, 32);
    priv_be[0] &= 127;
    priv_be[0] |= 64;
    priv_be[31] &= 248;
    gcry_mpi_scan(&mpi, GCRYMPI_FMT_USG, priv_be, 32, NULL);

    if (gcry_mpi_ec_new(&ctx, NULL, "Curve25519")) {
        /* Should not happen, possibly out-of-memory. */
        goto leave;
    }

    /* Compute Q = nP */
    Q = gcry_mpi_point_new(0);
    P = gcry_mpi_point_set(NULL, mpi_p, NULL, GCRYMPI_CONST_ONE);
    gcry_mpi_ec_mul(Q, mpi, P, ctx);

    /* Note: mpi is reused to store the result. */
    if (gcry_mpi_ec_get_affine(mpi, NULL, Q, ctx)) {
        /* Infinity. */
        goto leave;
    }

    if (gcry_mpi_print(GCRYMPI_FMT_USG, result_be, 32, &result_len, mpi)) {
        /* Should not happen, possibly out-of-memory. */
        goto leave;
    }
    copy_and_reverse(q, result_be, result_len);
    r = 0;

leave:
    gcry_mpi_point_release(P);
    gcry_mpi_point_release(Q);
    gcry_ctx_release(ctx);
    gcry_mpi_release(mpi);
    /* XXX erase priv_be and result_be */
    return r;
}


static void dh_x25519(wg_key *shared_secret, const wg_key *priv, const wg_key *pub) {
	unsigned char p_be[32];
	gcry_mpi_t mpi_p = NULL;

	copy_and_reverse(p_be, (const char *)pub, 32);
	/* Clear unused bit. */
	p_be[0] &= 0x7f;
	gcry_mpi_scan(&mpi_p, GCRYMPI_FMT_USG, p_be, 32, NULL);
	x25519_mpi((char *)shared_secret, (const char *)priv, mpi_p);
	gcry_mpi_release(mpi_p);
}

void hex_dump(const void * data, size_t len) {
	for( int i = 0; i < len; i++ ) {
		printf("%02x ", *(const u_char *)(data+i));
		if( i % 16 == 15 ) {
			printf("\n");
		}
	}
	printf("\n");
}

bool wg_mac_verify(const u_char *packet) {
	bool ok = false;
	gcry_md_hd_t hd;
	if (gcry_md_open(&hd, GCRY_MD_BLAKE2S_128, 0) == 0) {
		gcry_error_t r;
		// not documented by Libgcrypt, but required for keyed blake2s
		r = gcry_md_setkey(hd, mac1_key, 32);
		if( r != 0 ) {
			return ok;
		}
		gcry_md_write(hd, packet, 116);
		ok = memcmp((packet+116), gcry_md_read(hd, 0), 16) == 0;
		gcry_md_close(hd);
	}
	return ok;
}

void process_wg_initiation(const u_char *packet, uint16_t len) {
	if(len < 148)
		return;
	if(!wg_mac_verify(packet))
		return;
	wg_key ekey_pub;
	memcpy(ekey_pub, packet+8, 32);

	wg_key decrypted_key;
	wg_key encrypted_key;
	memcpy(encrypted_key, packet+40, 32);
	u_char auth_tag[16];
	memcpy(auth_tag, packet+72, 16);
	wg_key c_and_k[2], h;
	wg_key *c = &c_and_k[0], *k = &c_and_k[1];
	// c = Hash(CONSTRUCTION)
	memcpy(c, hash_of_construction, 32);
	// h = Hash(c || IDENTIFIER)
	memcpy(h, hash_of_c_identifier, 32);
	// h = Hash(h || Spub_r)
	wg_mix_hash(&h, &server_pub_key, 32);
	// c = KDF1(c, msg.ephemeral)
	wg_kdf(c, ekey_pub, 32, 1, c);
	// h = Hash(h || msg.ephemeral)
	wg_mix_hash(&h, ekey_pub, 32);
	//  dh1 = DH(Spriv_r, msg.ephemeral)
	wg_key dh1 = {0};
	dh_x25519(&dh1, &server_priv_key, &ekey_pub);
	// (c, k) = KDF2(c, dh1)
	wg_kdf(c, dh1, 32, 2, c_and_k);
	// Spub_i = AEAD-Decrypt(k, 0, msg.static, h)
	{
		gcry_cipher_hd_t    hd;
		if(gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0)) {
			return;
		}
		if (gcry_cipher_setkey(hd, k, 32)) {
			gcry_cipher_close(hd);
			return;
		}

		u_char nonce[12] = {0};
		if(gcry_cipher_setiv(hd, nonce, 12)) {
			gcry_cipher_close(hd);
			return;
		}
		if(gcry_cipher_authenticate(hd, h, 32)) {
			gcry_cipher_close(hd);
			return;
		}
		if(gcry_cipher_decrypt(hd, decrypted_key, 32, encrypted_key, 32)) {
			gcry_cipher_close(hd);
			return;
		}
		if(gcry_cipher_checktag(hd, auth_tag, 16)) {
			gcry_cipher_close(hd);
			return;
		}

		gcry_cipher_close(hd);
	}

	add_key_to_wg(decrypted_key);
	return;
}

void apply_bpf4(int sock, uint16_t port) {
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 22),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, port, 0, 3),
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 28),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x01, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, -1),
		BPF_STMT(BPF_RET + BPF_K, 0)
	};

	struct sock_fprog filter_prog = {
		.len = sizeof(filter) / sizeof(filter[0]),
		.filter = filter
	};

	if(setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog, sizeof(filter_prog)) < 0) {
		perror("setsockopt(4,bpf)");
		exit(1);
	}
}

void apply_bpf6(int sock, uint16_t port) {
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 2),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, port, 0, 3),
		BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 8),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x01, 0, 1),
		BPF_STMT(BPF_RET + BPF_K, -1),
		BPF_STMT(BPF_RET + BPF_K, 0)
	};

	struct sock_fprog filter_prog = {
		.len = sizeof(filter) / sizeof(filter[0]),
		.filter = filter
	};

	if(setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog, sizeof(filter_prog)) < 0) {
		perror("setsockopt(6,bpf)");
		exit(1);
	}
}

int main(int argc, char **argv) {
	if( argc != 4 ) {
		printf("usage: %s <net interface> <wg interface> <vxlan interface>\n", argv[0]);
		return 1;
	}

	char *device_name = argv[1];
	wg_device_name = argv[2];
	vx_device_name = argv[3];
	uint16_t port;

	// make output line buffered
	setvbuf(stdout, NULL, _IOLBF, 0);

	{
#define NEED_LIBGCRYPT_VERSION "1.8.0"
		if(!gcry_check_version (NEED_LIBGCRYPT_VERSION)) {
			printf("libgcrypt is too old (need %s, have %s)\n",
					NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
			return 1;
		}
		gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
		gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
		gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
		gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	}

	{
		wg_device *device;
		if(wg_get_device(&device, wg_device_name) < 0) {
			printf("Unable to get wg device\n");
			return 1;
		}

		if(device->flags & WGDEVICE_HAS_PRIVATE_KEY) {
			memcpy(&server_priv_key, device->private_key, 32);
			memcpy(&server_pub_key, device->public_key, 32);
			gcry_md_hd_t hd;
			if( gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0) != 0 ) {
				return 1;
			}
			const char wg_label_mac1[] = "mac1----";
			gcry_md_write(hd, wg_label_mac1, strlen(wg_label_mac1));
			gcry_md_write(hd, server_pub_key, sizeof(wg_key));
			memcpy(mac1_key, gcry_md_read(hd, 0), sizeof(wg_key));
			gcry_md_close(hd);
		}
		else {
			printf("%s has no private key\n", wg_device_name);
			return 1;
		}

		port = device->listen_port; 

		init_key_tree(&key_tree);
		wg_peer *peer;
		wg_for_each_peer(device, peer) {
			add_key_to_tree(key_tree, peer->public_key);
		}

		static const char construction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
		gcry_md_hash_buffer(GCRY_MD_BLAKE2S_256, hash_of_construction, construction, strlen(construction));

		static const char wg_identifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
		memcpy(&hash_of_c_identifier, hash_of_construction, sizeof(wg_key));
		wg_mix_hash(&hash_of_c_identifier, wg_identifier, strlen(wg_identifier));

		wg_free_device(device);
	}

	size_t device_name_len = strnlen(device_name, IFNAMSIZ);

	int sockfd4 = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if( sockfd4 < 0) {
		perror("socket 4");
		return 1;
	}
	if(setsockopt(sockfd4, SOL_SOCKET, SO_BINDTODEVICE, device_name, device_name_len) < 0) {
		perror("setsockopt(4,bindtodevice)");
		exit(1);
	}
	apply_bpf4(sockfd4, port);

	int sockfd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
	if( sockfd6 < 0) {
		perror("socket 6");
		return 1;
	}
	if(setsockopt(sockfd6, SOL_SOCKET, SO_BINDTODEVICE, device_name, device_name_len) < 0) {
		perror("setsockopt(6,bindtodevice)");
		exit(1);
	}
	apply_bpf6(sockfd6, port);

	struct pollfd pollfds[2];
	pollfds[0].fd = sockfd4;
	pollfds[0].events = POLLIN;
	pollfds[1].fd = sockfd6;
	pollfds[1].events = POLLIN;

	char buf[2048];

	pthread_t flush_thread;

	{
		int rc = pthread_create( &flush_thread, NULL, &flush_stale_peers, NULL );
		if( rc ) {
			printf("Could not create flush_stale_peers thread\n");
			return 1;
		}
	}


	signal(SIGTERM, signal_handler);

	printf("running...\n");

	while( run ) {
		int rc = poll(pollfds, 2, 1000);
		if( rc < 0 ) {
			perror("poll");
			run = false;
			break;
		}
		if( rc == 0 )
			continue;
		if(pollfds[0].revents & POLLIN) {
			int len = recv(sockfd4, &buf, 2048, 0);
			if(len < 0) {
				perror("recv");
				run = false;
				break;
			}
			if(len > 28)
				process_wg_initiation(buf+28, len-28);
		}
		if(pollfds[1].revents & POLLIN) {
			int len = recv(sockfd6, &buf, 2048, 0);
			if(len < 0) {
				perror("recv");
				run = false;
				break;
			}
			if(len > 8)
				process_wg_initiation(buf+8, len-8);
		}
	}

	close(sockfd4);
	close(sockfd6);

	pthread_join( flush_thread, NULL );

	free_tree(key_tree);

	return 0;
}
