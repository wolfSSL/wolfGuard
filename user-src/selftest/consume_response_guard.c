// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models wg_noise_handshake_consume_response()'s commit-time guard: a
 * concurrent create_initiation retransmit restores the same state enum while
 * replacing the ephemeral private key, so the state check alone is insufficient.
 *   cc consume_response_guard.c -o t && ./t              # fixed: passes
 *   cc -DOLD consume_response_guard.c -o t && ./t        # old: asserts
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define KEY_LEN 32
#define CREATED_INITIATION 1

/* returns 1 if the consumer is allowed to commit E1-derived state */
static int guard_passes(int snap_state, int cur_state,
			const unsigned char *snap_eph,
			const unsigned char *cur_eph, size_t n)
{
#ifdef OLD
	(void)snap_eph;
	(void)cur_eph;
	(void)n;
	return cur_state == snap_state;
#else
	return cur_state == snap_state && memcmp(cur_eph, snap_eph, n) == 0;
#endif
}

int main(void)
{
	unsigned char e1[KEY_LEN], e2[KEY_LEN];

	memset(e1, 0xE1, sizeof e1);
	memset(e2, 0xE2, sizeof e2);

	/* no race: ephemeral unchanged -> commit proceeds */
	assert(guard_passes(CREATED_INITIATION, CREATED_INITIATION,
			    e1, e1, KEY_LEN) == 1);

	/* race: retransmit restored the state enum but swapped E1 -> E2,
	 * the consumer must abort rather than clobber E2 */
	assert(guard_passes(CREATED_INITIATION, CREATED_INITIATION,
			    e1, e2, KEY_LEN) == 0);

	printf("consume_response guard: ephemeral swap detected, commit aborted\n");
	return 0;
}
