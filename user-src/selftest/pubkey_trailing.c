// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Checks pubkey_main()'s trailing-character validation: a literal NUL byte
 * (getc() returns 0) must be rejected, not silently consumed.
 *   cc -I.. pubkey_trailing.c -o t && ./t              # fixed: passes
 *   cc -DOLD_PREDICATE -I.. pubkey_trailing.c -o t && ./t  # old: asserts
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>

#include "ctype.h"

/* returns 1 if trailing characters are found (reject), 0 if clean (accept) */
static int check_trailing(const char *buf, size_t len)
{
	size_t pos = 0;

	for (;;) {
		int trailing_char = (pos < len) ? (unsigned char)buf[pos++] : EOF;
#ifdef OLD_PREDICATE
		if (!trailing_char || char_is_space(trailing_char))
			continue;
#else
		if (trailing_char != EOF && char_is_space(trailing_char))
			continue;
#endif
		if (trailing_char == EOF)
			return 0;
		return 1;
	}
}

int main(void)
{
	/* a NUL byte after the key must be rejected */
	assert(check_trailing("\0", 1) == 1);
	/* a NUL followed by garbage must be rejected */
	assert(check_trailing("\0X", 2) == 1);
	/* trailing whitespace then EOF is clean */
	assert(check_trailing(" \n\t", 3) == 0);
	/* immediate EOF is clean */
	assert(check_trailing("", 0) == 0);

	printf("pubkey trailing-char check: NUL rejected, whitespace allowed\n");
	return 0;
}
