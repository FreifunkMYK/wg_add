#include "wireguard.h"

struct key_tree {
	struct key_tree * next[256];
	struct key_list * list;
};

struct key_list {
	wg_key key;
	struct key_list * next;
};

void init_key_tree(struct key_tree ** tree);
void add_key_to_tree(struct key_tree * tree, const u_char *key);
bool key_in_tree(struct key_tree * tree, const u_char *key);
void remove_key_from_tree(struct key_tree * tree, const u_char *key);
void free_tree(struct key_tree * tree);
