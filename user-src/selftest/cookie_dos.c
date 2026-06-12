// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models wg_cookie_validate_packet()'s under-load path: a rate-limited flooding
 * source must be rejected before the heap-allocating HMAC make_cookie() runs.
 *   cc cookie_dos.c -o t && ./t              # fixed: passes
 *   cc -DOLD cookie_dos.c -o t && ./t        # old: asserts
 */

#include <assert.h>
#include <stdio.h>

enum { INVALID_MAC, VALID_MAC_BUT_NO_COOKIE,
       VALID_MAC_WITH_COOKIE_BUT_RATELIMITED, VALID_MAC_WITH_COOKIE };

static int make_cookie_calls;

static int validate(int check_cookie, int ratelimiter_allows, int mac2_valid)
{
	int ret = VALID_MAC_BUT_NO_COOKIE;

	if (!check_cookie)
		return ret;
#ifdef OLD
	++make_cookie_calls;
	if (!mac2_valid)
		return VALID_MAC_BUT_NO_COOKIE;
	ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
	if (!ratelimiter_allows)
		return ret;
	return VALID_MAC_WITH_COOKIE;
#else
	ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
	if (!ratelimiter_allows)
		return ret;
	++make_cookie_calls;
	if (!mac2_valid)
		return VALID_MAC_BUT_NO_COOKIE;
	return VALID_MAC_WITH_COOKIE;
#endif
}

int main(void)
{
	int r;

	/* flooding source, token bucket exhausted: must be dropped with no HMAC */
	make_cookie_calls = 0;
	r = validate(1 /*under load*/, 0 /*rate-limited*/, 0 /*no cookie*/);
	assert(r == VALID_MAC_WITH_COOKIE_BUT_RATELIMITED);
	assert(make_cookie_calls == 0);

	/* legitimate within-budget first contact still gets a cookie reply */
	make_cookie_calls = 0;
	r = validate(1, 1 /*allowed*/, 0);
	assert(r == VALID_MAC_BUT_NO_COOKIE);
	assert(make_cookie_calls == 1);

	printf("cookie validate: rate-limited flood rejected before make_cookie\n");
	return 0;
}
