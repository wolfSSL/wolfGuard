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
#include "ipc.h"

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

#if defined(IPC_SUPPORTS_KERNEL_INTERFACE) && !defined(NO_IPC_LLCRYPTO)

int genkey_main(int argc, char *argv[])
{
	uint8_t *privkey = NULL;
	size_t privkey_len;
	char *privkey_base64 = NULL;
	size_t privkey_base64_len;
	int ret;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}
	ret = ipc_generate_privkey(&privkey, &privkey_len, NULL /* pubkey */, NULL /* pubkey_len */);
	if (ret) {
		fprintf(stderr, "ipc_generate_privkey() failed: %s.\n", strerror(-ret));
		return ret;
	}

	privkey_base64_len = WG_BASE64_LEN(privkey_len);
	privkey_base64 = (char *)malloc(privkey_base64_len);
	if (! privkey_base64) {
		fprintf(stderr, "malloc: %m\n");
		goto out;
	}

	if (!wg_to_base64(privkey_base64, privkey_base64_len, privkey, privkey_len)) {
		fprintf(stderr, "wg_to_base64() failed.\n");
		goto out;
	}

	puts(privkey_base64);

	ret = 0;

out:

	memset(privkey, 0, privkey_len);
	free(privkey);
	if (privkey_base64) {
		memset(privkey_base64, 0, privkey_base64_len);
		free(privkey_base64);
	}

	return ret;
}

int genpsk_main(int argc, char *argv[])
{
	uint8_t *psk = NULL;
	size_t psk_len;
	char *psk_base64 = NULL;
	size_t psk_base64_len;
	int ret;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

	ret = ipc_generate_psk(&psk, &psk_len);
	if (ret) {
		fprintf(stderr, "ipc_generate_psk() failed: %s.\n", strerror(-ret));
		return ret;
	}

	psk_base64_len = WG_BASE64_LEN(psk_len);
	psk_base64 = (char *)malloc(psk_base64_len);
	if (! psk_base64) {
		fprintf(stderr, "malloc: %m\n");
		goto out;
	}

	if (!wg_to_base64(psk_base64, psk_base64_len, psk, psk_len)) {
		fprintf(stderr, "wg_to_base64() failed.\n");
		goto out;
	}

	puts(psk_base64);

	ret = 0;

out:

	memset(psk, 0, psk_len);
	free(psk);
	if (psk_base64) {
		memset(psk_base64, 0, psk_base64_len);
		free(psk_base64);
	}

	return ret;
}

#else /* !IPC_SUPPORTS_KERNEL_INTERFACE || NO_IPC_LLCRYPTO */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

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

int genpsk_main(int argc, char *argv[])
{
	WC_RNG rng;
	int rng_inited = 0;
	byte psk[WG_SYMMETRIC_KEY_LEN];
	char psk_base64[WG_BASE64_LEN(WG_SYMMETRIC_KEY_LEN)];
	int ret;

	if (argc != 1) {
		fprintf(stderr, "Usage: %s %s\n", PROG_NAME, argv[0]);
		return 1;
	}

	ret = wc_InitRng(&rng);
	if (ret) {
		fprintf(stderr, "wc_InitRng() failed: %s.\n", wc_GetErrorString(ret));
		goto out;
	}
	rng_inited = 1;

	ret = wc_RNG_GenerateBlock(&rng, psk, sizeof psk);
	if (ret) {
		fprintf(stderr, "wc_RNG_GenerateBlock() failed: %s.\n", wc_GetErrorString(ret));
		goto out;
	}

	if (!wg_to_base64(psk_base64, sizeof(psk_base64), psk, sizeof psk)) {
		fprintf(stderr, "wg_to_base64() failed.\n");
		goto out;
	}

	puts(psk_base64);

	ret = 0;

out:

	memset(psk, 0, sizeof psk);
	memset(psk_base64, 0, sizeof psk_base64);
	if (rng_inited)
		wc_FreeRng(&rng);

	return ret;
}

#endif /* !IPC_SUPPORTS_KERNEL_INTERFACE || NO_IPC_LLCRYPTO */
