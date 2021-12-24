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

#include "blake2s.h"
#include "curve25519.h"
#include "md5.h"
#include "chacha20poly1305.h"
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
	struct md5_state state;
	md5_init(&state);
	md5_update(&state, key_str, sizeof(wg_key_b64_string)-1);
	md5_update(&state, "\n", 1);
	md5_final(&state, md5);
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
		strncpy(device.name, wg_device_name, IFNAMSIZ - 1);
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
		strncpy(device.name, wg_device_name, IFNAMSIZ - 1);
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
		} while( run && diff.tv_sec < 300 );

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

void wg_mix_hash(wg_key *h, const void * data, size_t data_len) {
	struct blake2s_state blake;

	blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, (uint8_t *)h, sizeof(wg_key));
	blake2s_update(&blake, data, data_len);
	blake2s_final(&blake, (uint8_t *)h);
}

static void wg_kdf(const wg_key *key, const u_char *input, size_t input_len, int n, wg_key *out)
{
	uint8_t output[BLAKE2S_HASH_SIZE + 1];
	uint8_t secret[BLAKE2S_HASH_SIZE];

	blake2s256_hmac(secret, input, (uint8_t *)key, input_len, 32);
	output[0] = 1;
	for (size_t offset = 0; offset < n; offset++) {
		output[BLAKE2S_HASH_SIZE] = offset + 1;
		blake2s256_hmac(output, output, secret, (offset == 0) ? 1 : (BLAKE2S_HASH_SIZE + 1), BLAKE2S_HASH_SIZE); 
		memcpy(out + offset, output, BLAKE2S_HASH_SIZE);
	}

	memset(secret, 0, BLAKE2S_HASH_SIZE);
	memset(output, 0, BLAKE2S_HASH_SIZE + 1);
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
	uint8_t computed_mac[16];
	blake2s(computed_mac, packet, mac1_key, 16, 116, 32);
	return memcmp((packet+116), computed_mac, 16) == 0;
}

void process_wg_initiation(const u_char *packet, uint16_t len) {
	if(len < 148)
		return;
	if(!wg_mac_verify(packet))
		return;
	wg_key ekey_pub;
	memcpy(ekey_pub, packet+8, 32);

	wg_key decrypted_key;
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
	curve25519((uint8_t *)&dh1, (uint8_t *)&server_priv_key, (uint8_t *)&ekey_pub);
	// (c, k) = KDF2(c, dh1)
	wg_kdf(c, dh1, 32, 2, c_and_k);
	// Spub_i = AEAD-Decrypt(k, 0, msg.static, h)
	if(!chacha20poly1305_decrypt(decrypted_key, packet+40, 48, h, 32, (uint8_t *)k))
		return;

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
	if( argc != 3 ) {
		printf("usage: %s <net interface> <wg interface>\n", argv[0]);
		return 1;
	}

	char *device_name = argv[1];
	wg_device_name = argv[2];
	uint16_t port;

	// make output line buffered
	setvbuf(stdout, NULL, _IOLBF, 0);

	{
		wg_device *device;
		if(wg_get_device(&device, wg_device_name) < 0) {
			printf("Unable to get wg device\n");
			return 1;
		}

		if(device->flags & WGDEVICE_HAS_PRIVATE_KEY) {
			memcpy(&server_priv_key, device->private_key, 32);
			memcpy(&server_pub_key, device->public_key, 32);
			struct blake2s_state blake;
			const char wg_label_mac1[] = "mac1----";
			blake2s_init(&blake, BLAKE2S_HASH_SIZE);
			blake2s_update(&blake, wg_label_mac1, strlen(wg_label_mac1));
			blake2s_update(&blake, server_pub_key, sizeof(wg_key));
			blake2s_final(&blake, mac1_key);
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
		blake2s(hash_of_construction, construction, NULL, BLAKE2S_HASH_SIZE, strlen(construction), 0);

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
