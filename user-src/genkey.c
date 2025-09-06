// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#ifndef MAC_OS_X_VERSION_10_12
#define MAC_OS_X_VERSION_10_12 101200
#endif
#if MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12
#include <sys/random.h>
#endif
#endif

#include "encoding.h"
#include "subcommands.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifndef _WIN32
static inline bool __attribute__((__warn_unused_result__)) get_random_bytes(uint8_t *out, size_t len)
{
	ssize_t ret = 0;
	size_t i;
	int fd;

	if (len > 256) {
		errno = EOVERFLOW;
		return false;
	}

#if defined(__OpenBSD__) || (defined(__APPLE__) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_12) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)))
	if (!getentropy(out, len))
		return true;
#endif

#if defined(__NR_getrandom) && defined(__linux__)
	if (syscall(__NR_getrandom, out, len, 0) == (ssize_t)len)
		return true;
#endif

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return false;
	for (errno = 0, i = 0; i < len; i += ret, ret = 0) {
		ret = read(fd, out + i, len - i);
		if (ret <= 0) {
			ret = errno ? -errno : -EIO;
			break;
		}
	}
	close(fd);
	errno = -ret;
	return i == len;
}
#else
#include <ntsecapi.h>
static inline bool __attribute__((__warn_unused_result__)) get_random_bytes(uint8_t *out, size_t len)
{
        return RtlGenRandom(out, len);
}
#endif


int genkey_main(int argc, char *argv[])
{
	WC_RNG rng;
	int rng_inited = 0;
        ecc_key key;
        int key_inited = 0;
	byte exported_private[WG_PRIVATE_KEY_LEN];
	char exported_private_base64[WG_BASE64_LEN(WG_PRIVATE_KEY_LEN)];
        int ret;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

        ret = wc_ecc_init(&key);
        if (ret) {
		fprintf(stderr, "wc_ecc_init() failed: %s.\n", wc_GetErrorString(ret));
		goto out;
        }
        key_inited = 1;

        ret = wc_InitRng(&rng);
        if (ret) {
		fprintf(stderr, "wc_InitRng() failed: %s.\n", wc_GetErrorString(ret));
		goto out;
        }
        rng_inited = 1;

        ret = wc_ecc_make_key_ex(
		&rng,
		0 /* keysize -- use curve_id to designate the curve. */,
		&key,
		WG_CURVE_ID);
        if (ret)
		goto out;

        {
		word32 outLen = (word32)sizeof(exported_private);
		PRIVATE_KEY_UNLOCK();
		ret = wc_ecc_export_private_only(&key, exported_private, &outLen);
		PRIVATE_KEY_LOCK();
		if (ret) {
			fprintf(stderr, "wc_ecc_export_private_only() returned error: %s.\n", wc_GetErrorString(ret));
			goto out;
		}
		if (outLen != (word32)sizeof(exported_private)) {
			fprintf(stderr, "wc_ecc_export_private_only() returned wrong size key %u.\n", outLen);
			ret = WC_KEY_SIZE_E;
			goto out;
		}
        }

	if (!wg_to_base64(exported_private_base64, sizeof(exported_private_base64), exported_private, sizeof(exported_private))) {
		fprintf(stderr, "wg_to_base64() failed.\n");
		goto out;
        }

	puts(exported_private_base64);

        ret = 0;

out:

	memset(exported_private, 0, sizeof(exported_private));
	memset(exported_private_base64, 0, sizeof(exported_private_base64));
        if (rng_inited)
		wc_FreeRng(&rng);
	if (key_inited)
		wc_ecc_free(&key);

        return ret;
}
