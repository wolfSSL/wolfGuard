// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models wg_ratelimiter_allow()'s insert phase: two concurrent first packets
 * from the same source both miss the RCU search, so the insert under table_lock
 * must re-scan and reuse an existing entry instead of creating a duplicate.
 *   cc ratelimiter_dup.c -o t && ./t              # fixed: passes
 *   cc -DOLD ratelimiter_dup.c -o t && ./t        # old: asserts
 */

#include <assert.h>
#include <stdio.h>

#define BUCKET_MAX 8

struct entry { int net, ip; };

static struct entry bucket[BUCKET_MAX];
static int bucket_len;
static int total_entries;

static struct entry *bucket_find(int net, int ip)
{
	int i;

	for (i = 0; i < bucket_len; ++i)
		if (bucket[i].net == net && bucket[i].ip == ip)
			return &bucket[i];
	return NULL;
}

/* the table_lock-protected insert phase, after both racers missed the search */
static void insert_phase(int net, int ip)
{
	++total_entries;                       /* atomic_inc_return(&total_entries) */
#ifndef OLD
	if (bucket_find(net, ip)) {            /* re-scan under table_lock */
		--total_entries;              /* discard candidate */
		return;
	}
#endif
	bucket[bucket_len].net = net;
	bucket[bucket_len].ip = ip;
	++bucket_len;
}

int main(void)
{
	/* two first packets from the same (net, ip) race the insert */
	insert_phase(1, 0x0a000001);
	insert_phase(1, 0x0a000001);

	assert(bucket_len == 1);
	assert(total_entries == 1);

	printf("ratelimiter: concurrent first packets coalesce to one entry\n");
	return 0;
}
