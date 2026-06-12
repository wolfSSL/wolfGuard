// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models __compat_udp_sock_create()'s bindv6only save/restore: two concurrent
 * creates that each toggle the sysctl must leave it at its original value. The
 * documented race interleaves save/restore and leaks the toggled value; the
 * mutex serializes the section so the original is always restored.
 *   cc bindv6only_race.c -o t && ./t              # fixed: passes
 *   cc -DOLD bindv6only_race.c -o t && ./t        # old: asserts
 */

#include <assert.h>
#include <stdio.h>

static int sysctl_bindv6only;

static void run_two_creates(void)
{
	int saved_a, saved_b;

#ifdef OLD
	saved_a = sysctl_bindv6only; sysctl_bindv6only = 1;   /* A: save(0), set */
	saved_b = sysctl_bindv6only; sysctl_bindv6only = 1;   /* B: save(1!), set */
	sysctl_bindv6only = saved_a;                          /* A: restore(0) */
	sysctl_bindv6only = saved_b;                          /* B: restore(1) leak */
#else
	/* serialized under bindv6only_lock: each save/set/restore is atomic */
	saved_a = sysctl_bindv6only; sysctl_bindv6only = 1; sysctl_bindv6only = saved_a;
	saved_b = sysctl_bindv6only; sysctl_bindv6only = 1; sysctl_bindv6only = saved_b;
#endif
}

int main(void)
{
	sysctl_bindv6only = 0;
	run_two_creates();
	assert(sysctl_bindv6only == 0);   /* original value restored after both */

	printf("bindv6only: concurrent creates restore original sysctl\n");
	return 0;
}
