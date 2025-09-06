// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <errno.h>
#include <stdio.h>

#include "encoding.h"
#include "subcommands.h"
#include "ctype.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

int pubkey_main(int argc, char *argv[])
{
	uint8_t key[WG_KEY_LEN_MAX];
	char base64[WG_BASE64_LEN(WG_KEY_LEN_MAX)];
	int trailing_char;
	ecc_key key_ecc;
	int key_ecc_inited;
	WC_RNG rng;
	int rng_inited = 0;
	int ret = 1;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		goto out;
	}

        ret = wc_ecc_init(&key_ecc);
        if (ret) {
		fprintf(stderr, "wc_ecc_init() returned error: %s.\n", wc_GetErrorString(ret));
		goto out;
	}
        key_ecc_inited = 1;

	if (fread(base64, 1, WG_BASE64_LEN(WG_PRIVATE_KEY_LEN) - 1, stdin) != WG_BASE64_LEN(WG_PRIVATE_KEY_LEN) - 1) {
		errno = EINVAL;
		fprintf(stderr, "%s: Key is not the correct length or format\n", PROG_NAME);
		goto out;
	}
	base64[sizeof(base64) - 1] = '\0';

	for (;;) {
		trailing_char = getc(stdin);
		if (!trailing_char || char_is_space(trailing_char))
			continue;
		if (trailing_char == EOF)
			break;
		fprintf(stderr, "%s: Trailing characters found after key\n", PROG_NAME);
		goto out;
	}

	if (!wg_from_base64(key, WG_PRIVATE_KEY_LEN, base64, WG_BASE64_LEN(WG_PRIVATE_KEY_LEN) - 1)) {
		fprintf(stderr, "%s: wg_from_base64(): Key is not the correct length or format\n", PROG_NAME);
		goto out;
	}

        ret = wc_ecc_import_private_key_ex(key, WG_PRIVATE_KEY_LEN,
                                           NULL, 0, &key_ecc, WG_CURVE_ID);
        if (ret) {
		fprintf(stderr, "wc_ecc_import_private_key_ex() returned error: %s.\n", wc_GetErrorString(ret));
		goto out;
	}

	ret = wc_InitRng(&rng);
	if (ret) {
		fprintf(stderr, "wc_InitRng() returned error: %s.\n", wc_GetErrorString(ret));
		goto out;
	}
	rng_inited = 1;

	ret = wc_ecc_make_pub_ex(&key_ecc, NULL /* pubOut */, &rng);
	if (ret) {
		fprintf(stderr, "wc_ecc_make_pub_ex() returned error: %s.\n", wc_GetErrorString(ret));
		goto out;
	}

	{
		word32 outLen = (word32)sizeof(key);
		PRIVATE_KEY_UNLOCK(); /* should not be needed, but is... */
		ret = wc_ecc_export_x963(&key_ecc, key, &outLen);
		PRIVATE_KEY_LOCK();
		if (ret) {
			fprintf(stderr, "wc_ecc_export_x963() returned error: %s.\n", wc_GetErrorString(ret));
			goto out;
		}
		if (outLen != WG_PUBLIC_KEY_LEN) {
			fprintf(stderr, "wc_ecc_export_x963() returned unexpected key length %u.\n", outLen);
			goto out;
		}
	}

	if (!wg_to_base64(base64, WG_BASE64_LEN(WG_PUBLIC_KEY_LEN), key, WG_PUBLIC_KEY_LEN)) {
		fprintf(stderr, "%s: wg_to_base64() failed for public key.\n", PROG_NAME);
		goto out;
	}
	puts(base64);

	ret = 0;

out:

	if (key_ecc_inited)
                wc_ecc_free(&key_ecc);
        if (rng_inited)
		wc_FreeRng(&rng);
	memset(key, 0, sizeof(key));
	memset(base64, 0, sizeof(base64));

	return ret;
}
