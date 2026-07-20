// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Checks userspace_set_device()'s IPC errno parse: an out-of-range reply such
 * as "errno=-2147483648" must not drive ret = -ret / errno = -ret into signed
 * overflow (UB), and must be rejected cleanly.
 *   cc -I.. errno_parse.c -o t && ./t          # fixed: passes
 *   cc -DOLD -I.. errno_parse.c -o t && ./t     # old: asserts
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>

static int parse_reply(FILE *f)
{
	int ret;
#ifdef OLD
	if (fscanf(f, "errno=%d\n\n", &ret) != 1)
		ret = errno ? -errno : -EPROTO;
	else
		ret = -ret;
#else
	unsigned long long e;

	if (fscanf(f, "errno=%llu\n\n", &e) != 1)
		ret = errno ? -errno : -EPROTO;
	else if (e > INT_MAX)
		ret = -EPROTO;
	else
		ret = -(int)e;
#endif
	errno = -ret;
	return ret;
}

int main(void)
{
	char attack[] = "errno=-2147483648\n\n";
	char normal[] = "errno=2\n\n";
	FILE *f;
	int r;

	f = fmemopen(attack, sizeof attack - 1, "r");
	assert(f);
	errno = 0;
	r = parse_reply(f);
	fclose(f);
	assert(r == -EPROTO);
	assert(errno == EPROTO);

	f = fmemopen(normal, sizeof normal - 1, "r");
	assert(f);
	errno = 0;
	r = parse_reply(f);
	fclose(f);
	assert(r == -2);

	printf("userspace_set_device errno parse: out-of-range rejected\n");
	return 0;
}
