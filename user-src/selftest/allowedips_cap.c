// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models the per-device allowed-IP node-count cap added to allowedips.c add()
 * and walk_remove_by_peer(): increment per allocated node, reject new prefixes
 * at the cap, decrement on free, reset on table free.
 *   cc allowedips_cap.c -o t && ./t
 */

#include <assert.h>
#include <stdio.h>

#define MAX_NODES 4

static unsigned long long node_count;

/* mirrors add(): exact-match reassign allocates nothing; a new prefix needs one
 * node, and a prefix split needs a second intermediate node. */
static int model_add(int new_prefix, int split)
{
	if (!new_prefix)
		return 0;
	if (node_count >= MAX_NODES)
		return -1;
	++node_count;
	if (split) {
		/* the intermediate split node is cap-checked too, so the cap is
		 * strict; on rejection the newnode count is unwound. */
		if (node_count >= MAX_NODES) {
			--node_count;
			return -1;
		}
		++node_count;
	}
	return 0;
}

/* mirrors walk_remove_by_peer()'s guarded decrement on each freed node */
static void model_free_one(void)
{
	if (node_count)
		--node_count;
}

int main(void)
{
	int i;

	/* fill to the cap with single-node prefixes */
	for (i = 0; i < MAX_NODES; ++i)
		assert(model_add(1, 0) == 0);
	assert(node_count == MAX_NODES);

	/* a further new prefix is rejected */
	assert(model_add(1, 0) == -1);

	/* an exact-match update at the cap still succeeds (no allocation) */
	assert(model_add(0, 0) == 0);

	/* freeing entries lets new prefixes back in */
	model_free_one();
	assert(model_add(1, 0) == 0);
	assert(node_count == MAX_NODES);

	/* a split with room for both nodes succeeds and never half-counts */
	model_free_one();
	model_free_one();
	assert(node_count == MAX_NODES - 2);
	assert(model_add(1, 1) == 0);
	assert(node_count == MAX_NODES);

	/* at the cap boundary a splitting insert is rejected rather than
	 * exceeding the cap by one */
	model_free_one();
	assert(node_count == MAX_NODES - 1);
	assert(model_add(1, 1) == -1);
	assert(node_count == MAX_NODES - 1);

	printf("allowedips cap: count tracked, strict cap on split, no underflow\n");
	return 0;
}
