// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Standalone check for terminal_sanitize():
 *   cc -I.. sanitize.c ../terminal.c -o sanitize && ./sanitize
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "terminal.h"

static int has_unsafe(const char *s)
{
	for (size_t i = 0; s[i]; ++i) {
		unsigned char c = (unsigned char)s[i];

		if (c < 0x20 || c >= 0x7f)
			return 1;
	}
	return 0;
}

int main(void)
{
	char out[64];
	char tiny[4];

	/* CSI / ANSI colour injection */
	terminal_sanitize("wg0\x1b[31mINJECT\x1b[0m", out, sizeof out);
	assert(!has_unsafe(out));
	assert(!strcmp(out, "wg0?[31mINJECT?[0m"));

	/* OSC window-title / clipboard, BEL terminator */
	terminal_sanitize("wg0\x1b]0;pwned\x07", out, sizeof out);
	assert(!has_unsafe(out));

	/* CR overwrite and embedded-newline log forgery */
	terminal_sanitize("legit\rFAKE\nMay 30 sudo: root", out, sizeof out);
	assert(!has_unsafe(out));

	/* printable input is preserved verbatim */
	terminal_sanitize("normal-wg1_2", out, sizeof out);
	assert(!strcmp(out, "normal-wg1_2"));

	/* truncation never overflows and always NUL-terminates */
	terminal_sanitize("abcdef", tiny, sizeof tiny);
	assert(!strcmp(tiny, "abc"));

	/* NULL input yields an empty string, no crash */
	terminal_sanitize(NULL, out, sizeof out);
	assert(out[0] == '\0');

	printf("terminal_sanitize: all checks passed\n");
	return 0;
}
