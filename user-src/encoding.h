/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2025 wolfSSL Inc. <info@wolfssl.com>
 */

#ifndef ENCODING_H
#define ENCODING_H

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include "containers.h"

#define WG_BASE64_LEN(x) ((((x) + 2) / 3) * 4 + 1)
#define WG_HEX_LEN(x) (((x) * 2) + 1)

bool wg_to_base64(char *base64, size_t base64_len, const uint8_t *raw, size_t raw_len);
bool wg_from_base64(uint8_t *raw, size_t raw_len, const char *base64, size_t base64_len);
bool wg_to_hex(char *hex, size_t hex_len, const uint8_t *raw, size_t raw_len);
bool wg_from_hex(uint8_t *raw, size_t raw_len, const char *hex, size_t hex_len);
bool wg_is_zero(const uint8_t *key, size_t key_len);

#endif
