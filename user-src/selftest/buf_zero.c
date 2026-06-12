// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models the mnlg_socket_close() zero-on-free contract (netlink.h): the netlink
 * scratch buffer carries private key / PSK bytes and must be scrubbed before
 * free. Exercises the real memzero_explicit().
 *   cc -I.. buf_zero.c -o buf_zero && ./buf_zero            # fixed: passes
 *   cc -DUNFIXED -I.. buf_zero.c -o buf_zero && ./buf_zero  # old: asserts
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "containers.h"

#define BUF_SIZE 8192
#define KEY_OFFSET 24
#define KEY_LEN 32

/* mirrors mnlg_socket_close(): with the fix, scrub nlg->buf before freeing */
static void close_buf(uint8_t *buf, size_t len)
{
#ifndef UNFIXED
	memzero_explicit(buf, len);
#endif
}

int main(void)
{
	uint8_t buf[BUF_SIZE];
	uint8_t secret[KEY_LEN];
	size_t i;
	int residue = 0;

	for (i = 0; i < KEY_LEN; ++i)
		secret[i] = (uint8_t)(0xCC + i);

	memset(buf, 0, sizeof buf);
	memcpy(buf + KEY_OFFSET, secret, KEY_LEN);   /* key lands in nlg->buf */

	close_buf(buf, sizeof buf);

	for (i = 0; i < KEY_LEN; ++i)
		residue |= (buf[KEY_OFFSET + i] == secret[i]);
	assert(!residue);

	printf("mnlg_socket_close: key buffer scrubbed before free\n");
	return 0;
}
