// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <string.h>
#include "encoding.h"

bool wg_is_zero(const uint8_t *key, size_t key_len)
{
	volatile uint8_t acc = 0;

	for (unsigned int i = 0; i < key_len; ++i) {
		acc |= key[i];
		asm volatile("" : "=r"(acc) : "0"(acc));
	}
	return 1 & ((acc - 1) >> 8);
}
