// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Standalone check for wg_from_base64() trailing-input rejection (LLCRYPTO path):
 *   cc -DIPC_SUPPORTS_KERNEL_INTERFACE -I.. base64.c ../encoding.c -o base64 && ./base64
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encoding.h"

int main(void)
{
	uint8_t key[32] = { 0 };
	uint8_t out[32];
	char b64[WG_BASE64_LEN(32)];
	char bad1[64];
	char bad4[64];
	size_t n;

	assert(wg_to_base64(b64, sizeof b64, key, sizeof key));
	n = strlen(b64);

	/* canonical encoding decodes cleanly */
	assert(wg_from_base64(out, sizeof out, b64, n));

	/* one trailing character after a complete decode must be rejected */
	strcpy(bad1, b64);
	strcat(bad1, "A");
	assert(!wg_from_base64(out, sizeof out, bad1, strlen(bad1)));

	/* a full trailing quartet after the padded final quartet must be rejected */
	strcpy(bad4, b64);
	strcat(bad4, "AAAA");
	assert(!wg_from_base64(out, sizeof out, bad4, strlen(bad4)));

	printf("wg_from_base64 LLCRYPTO: trailing-input rejection OK\n");
	return 0;
}
