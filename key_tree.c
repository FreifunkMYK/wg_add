#include "key_tree.h"
#include <stdlib.h>
#include <string.h>

#define TREE_DEPTH 2

struct key_list ** get_key_list(struct key_tree * tree, const u_char *key)
{
	struct key_tree * t = tree;
	struct key_tree ** next_t = NULL;
	for(size_t d = 0; d < TREE_DEPTH; d++) {
		next_t = &(t->next[key[d]]);
		if(!*next_t) {
			*next_t = calloc(1, sizeof(struct key_tree));
			if(!*next_t)
				return NULL;
		}
		t = *next_t;
	}
	return &(t->list);
}

void init_key_tree(struct key_tree ** tree)
{
	if( *tree )
		return;
	*tree = calloc(1, sizeof(struct key_tree));
}

void add_key_to_tree(struct key_tree * tree, const u_char *key)
{
	struct key_list ** tree_l = get_key_list(tree, key);
	if(!*tree_l) {
		*tree_l = calloc(1, sizeof(struct key_list));
		memcpy((*tree_l)->key, key, 32);
		return;
	}

	struct key_list * last_l;
	struct key_list * l = *tree_l;
	while( l ) {
		if(memcmp(l->key, key, 32) == 0)
			return;
		last_l = l;
		l = l->next;
	}
	l = calloc(1, sizeof(struct key_list));
	memcpy(l->key, key, 32);
	last_l->next = l;
}

bool key_in_tree(struct key_tree * tree, const u_char *key)
{
	struct key_list ** tree_l = get_key_list(tree, key);
	struct key_list * l = *tree_l;
	while( l ) {
		if(memcmp(l->key, key, 32) == 0)
			return true;
		l = l->next;
	}
	return false;
}

void remove_key_from_tree(struct key_tree * tree, const u_char *key)
{
	struct key_list ** tree_l = get_key_list(tree, key);
	struct key_list * last_l = NULL;
	struct key_list * l = *tree_l;
	while( l ) {
		if(memcmp(l->key, key, 32) == 0) {
			if( last_l ) {
				last_l->next = l->next;
				free(l);
			}
			else {
				*tree_l = l->next;
				free(l);
			}
			return;
		}
		last_l = l;
		l = l->next;
	}
}

void free_list(struct key_list * list)
{
	struct key_list * l = list;
	struct key_list * next_l;
	while( l ) {
		next_l = l->next;
		free(l);
		l = next_l;
	}
}

void free_tree(struct key_tree * tree)
{
	for(size_t i = 0; i < 256; i++) {
		if(tree->next[i]) {
			free_tree(tree->next[i]);
		}
	}
	free_list(tree->list);
	free(tree);
}
