// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models the out-path cleanup of wg_noise_handshake_create_initiation/response:
 * a generated ephemeral private key must be wiped when the handshake fails.
 *   cc handshake_zero.c -o t && ./t              # fixed: passes
 *   cc -DOLD -I.. handshake_zero.c -o t && ./t   # old: asserts
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define KEY_LEN 32

struct handshake {
	unsigned char ephemeral_private[KEY_LEN];
	int state;
};

/* returns 1 on success, 0 on failure; mirrors the create function's flow */
static int model_create(struct handshake *h, int succeed)
{
	int ret = 0;
	size_t i;

	for (i = 0; i < KEY_LEN; ++i)
		h->ephemeral_private[i] = 0xE1;   /* wc_ecc_make_keypair_exim */

	if (!succeed)
		goto out;                         /* a later crypto step fails */

	h->state = 1;
	ret = 1;
out:
#ifndef OLD
	if (!ret)
		memset(h->ephemeral_private, 0, KEY_LEN);
#endif
	return ret;
}

static int is_zero(const unsigned char *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; ++i)
		if (p[i])
			return 0;
	return 1;
}

int main(void)
{
	struct handshake h;

	memset(&h, 0, sizeof h);
	assert(model_create(&h, 1) == 1);
	assert(!is_zero(h.ephemeral_private, KEY_LEN));   /* success keeps the key */

	memset(&h, 0, sizeof h);
	assert(model_create(&h, 0) == 0);
	assert(is_zero(h.ephemeral_private, KEY_LEN));    /* failure wipes the key */

	printf("handshake create: ephemeral private wiped on failure\n");
	return 0;
}
