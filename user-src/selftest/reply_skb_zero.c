// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models the error-path cleanup of wg_nl_generate_privkey/psk: a key copied
 * into the reply skb via nla_put must be scrubbed before the skb is freed on a
 * local error path.
 *   cc reply_skb_zero.c -o t && ./t              # fixed: passes
 *   cc -DOLD reply_skb_zero.c -o t && ./t        # old: asserts
 */

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define KEY_LEN 32
#define HDR_LEN 20

int main(void)
{
	unsigned char reply[256];
	unsigned char secret[KEY_LEN];
	int reply_len;
	size_t i;
	int residue = 0;

	for (i = 0; i < KEY_LEN; ++i)
		secret[i] = (unsigned char)(0xC0 + i);

	memset(reply, 0, sizeof reply);
	/* nla_put(reply, WGDEVICE_A_PRIVATE_KEY, ...) copies the key into the skb */
	memcpy(reply + HDR_LEN, secret, KEY_LEN);
	reply_len = HDR_LEN + KEY_LEN;

	/* local error path: scrub the reply payload before nlmsg_free() */
#ifndef OLD
	memset(reply, 0, reply_len);   /* memzero_explicit(reply->data, reply->len) */
#endif

	for (i = 0; i < KEY_LEN; ++i)
		residue |= (reply[HDR_LEN + i] == secret[i]);
	assert(!residue);

	printf("reply skb: key scrubbed before free on error path\n");
	return 0;
}
