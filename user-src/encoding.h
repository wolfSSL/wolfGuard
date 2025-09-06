/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef ENCODING_H
#define ENCODING_H

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include "containers.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define WG_BASE64_LEN(x) ((((x) + 2) / 3) * 4 + 1)
#define WG_HEX_LEN(x) (((x) * 2) + 1)

static inline bool wg_to_base64(char *base64, size_t base64_len, const uint8_t *raw, size_t raw_len) {
    word32 base64_len_out;
    int ret;
    if ((raw_len > UINT_MAX) || (base64_len > UINT_MAX))
        return false;
    base64_len_out = (word32)base64_len;
    ret = Base64_Encode_NoNl(raw, (word32)raw_len, (byte *)base64, &base64_len_out);
    if (ret != 0) {
        fprintf(stderr, "Base64_Encode_NoNl() returned error: %s.\n", wc_GetErrorString(ret));
        memset(base64, 0, (word32)base64_len);
        return false;
    }
    if (base64_len_out != (word32)base64_len - 1)
    {
        fprintf(stderr, "Base64_Encode_NoNl() returned unexpected output length %u.\n", base64_len_out);
        memset(base64, 0, (word32)base64_len);
        return false;
    }
    return true;
}

static inline bool wg_from_base64(uint8_t *raw, size_t raw_len, const char *base64, size_t base64_len) {
    word32 raw_len_out;
    int ret;
    if ((raw_len > UINT_MAX) || (base64_len > UINT_MAX))
        return false;
    raw_len_out = (word32)raw_len;
    ret = Base64_Decode((byte *)base64, base64_len, raw, &raw_len_out);
    if (ret != 0) {
        fprintf(stderr, "Base64_Decode() returned error: %s.\n", wc_GetErrorString(ret));
        memset(raw, 0, (word32)raw_len);
        return false;
    }

    if (raw_len_out != (word32)raw_len)
    {
        fprintf(stderr, "Base64_Decode() returned unexpected output length %u.\n", raw_len_out);
        memset(raw, 0, (word32)raw_len);
        return false;
    }
    return true;
}

static inline bool wg_to_hex(char *hex, size_t hex_len, const uint8_t *raw, size_t raw_len) {
    word32 hex_len_out;
    if ((raw_len > UINT_MAX) || (hex_len > UINT_MAX))
        return false;
    hex_len_out = (word32)hex_len;
    if ((Base16_Encode(raw, (word32)raw_len, (byte *)hex, &hex_len_out) != 0) ||
        (hex_len_out != (word32)hex_len))
    {
        memset(hex, 0, (word32)hex_len);
        return false;
    }
    return true;
}

static inline bool wg_from_hex(uint8_t *raw, size_t raw_len, const char *hex, size_t hex_len) {
    word32 raw_len_out;
    if ((raw_len > UINT_MAX) || (hex_len > UINT_MAX))
        return false;
    raw_len_out = (word32)raw_len;
    if ((Base16_Decode((byte *)hex, hex_len, raw, &raw_len_out) != 0) ||
        (raw_len_out != (word32)raw_len))
    {
        memset(raw, 0, (word32)raw_len);
        return false;
    }
    return true;
}

bool wg_is_zero(const uint8_t *key, size_t key_len);

#endif
