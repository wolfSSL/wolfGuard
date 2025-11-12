// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2025 wolfSSL Inc. <info@wolfssl.com>
 */

#include <string.h>
#include "encoding.h"
#include "ipc.h" /* for IPC_SUPPORTS_KERNEL_INTERFACE */

#if defined(IPC_SUPPORTS_KERNEL_INTERFACE) && !defined(NO_IPC_LLCRYPTO)

/* these implementations are derived from wolfssl/wolfcrypt/src/coding.c.  by
 * adapting them here, we eliminate the dependency on libwolfssl when building
 * with kernel key op support.
 */

enum {
    BAD         = 0xFF,  /* invalid encoding */
    PAD         = '=',
    BASE64_MIN  = 0x2B,
    BASE16_MIN  = 0x30
};

static
const uint8_t base64Encode[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                              'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                              'U', 'V', 'W', 'X', 'Y', 'Z',
                              'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                              'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                              'u', 'v', 'w', 'x', 'y', 'z',
                              '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                              '+', '/'
                            };

/* make sure *i (idx) won't exceed max, store to out, raw means use e w/o
 * encode, 0 on success
 */
static inline bool base64_encode_1(uint8_t e, char* out, size_t *i, size_t maxSz,
                  int raw)
{
    /* check size */
    if (*i >= maxSz)
        return false;

    /* store it */
    if (raw)
        out[(*i)++] = e;
    else {
        if (e >= sizeof(base64Encode))
            return false;
        out[(*i)++] = base64Encode[e];
    }

    return true;
}

bool wg_to_base64(char *out, size_t outSpc, const uint8_t *in, size_t inLen)
{
    size_t i = 0,
           j = 0;

    size_t outSz = (inLen + 3 - 1) / 3 * 4;

    if (outSpc < outSz)
        return false;

    while (inLen > 2) {
        uint8_t b1 = in[j++];
        uint8_t b2 = in[j++];
        uint8_t b3 = in[j++];

        /* encoded idx */
        uint8_t e1 = b1 >> 2;
        uint8_t e2 = (uint8_t)(((b1 & 0x3) << 4) | (b2 >> 4));
        uint8_t e3 = (uint8_t)(((b2 & 0xF) << 2) | (b3 >> 6));
        uint8_t e4 = b3 & 0x3F;

        /* store */
        if ((! base64_encode_1(e1, out, &i, outSpc, 0)) ||
            (! base64_encode_1(e2, out, &i, outSpc, 0)) ||
            (! base64_encode_1(e3, out, &i, outSpc, 0)) ||
            (! base64_encode_1(e4, out, &i, outSpc, 0)))
        {
            return false;
        }

        inLen -= 3;
    }

    /* last integral */
    if (inLen) {
        int twoUint8_Ts = (inLen == 2);

        uint8_t b1 = in[j++];
        uint8_t b2 = (twoUint8_Ts) ? in[j++] : 0;

        uint8_t e1 = b1 >> 2;
        uint8_t e2 = (uint8_t)(((b1 & 0x3) << 4) | (b2 >> 4));
        uint8_t e3 = (uint8_t)((b2 & 0xF) << 2);

        if (! base64_encode_1(e1, out, &i, outSpc, 0))
            return false;
        if (! base64_encode_1(e2, out, &i, outSpc, 0))
            return false;
        if (twoUint8_Ts) {
            if (! base64_encode_1(e3, out, &i, outSpc, 0))
                return false;
        }
        else {
            if (! base64_encode_1('=', out, &i, outSpc, 1))
                return false;
        }
        /* fourth always pad */
        if (! base64_encode_1('=', out, &i, outSpc, 1))
            return false;
    }

    /* If the output buffer has a room for an extra uint8_t, add a null terminator */
    if (outSpc > i)
        out[i] = '\0';

    return true;
}

static inline uint8_t Base64_Char2Val_CT(uint8_t c)
{
    int v;
    int smallEnd   = (int)c - 0x7b;
    int smallStart = (int)c - 0x61;
    int bigEnd     = (int)c - 0x5b;
    int bigStart   = (int)c - 0x41;
    int numEnd     = (int)c - 0x3a;
    int numStart   = (int)c - 0x30;
    int slashEnd   = (int)c - 0x30;
    int slashStart = (int)c - 0x2f;
    int plusEnd    = (int)c - 0x2c;
    int plusStart  = (int)c - 0x2b;

    v  = ((smallStart >> 8) ^ (smallEnd >> 8)) & (smallStart + 26 + 1);
    v |= ((bigStart   >> 8) ^ (bigEnd   >> 8)) & (bigStart   +  0 + 1);
    v |= ((numStart   >> 8) ^ (numEnd   >> 8)) & (numStart   + 52 + 1);
    v |= ((slashStart >> 8) ^ (slashEnd >> 8)) & (slashStart + 63 + 1);
    v |= ((plusStart  >> 8) ^ (plusEnd  >> 8)) & (plusStart  + 62 + 1);

    return (uint8_t)(v - 1);
}

bool wg_from_base64(uint8_t *out, size_t outLen, const char *in, size_t inLen) {
    size_t i = 0;
    size_t j = 0;

    while (inLen > 3) {
        int pad3 = 0;
        int pad4 = 0;
        uint8_t b1, b2, b3;
        uint8_t e1, e2, e3, e4;

        if (inLen < 4)
            return false;
        e1 = in[j++];
        e2 = in[j++];
        e3 = in[j++];
        e4 = in[j++];
        inLen -= 4;

        if (e3 == PAD)
            pad3 = 1;
        if (e4 == PAD)
            pad4 = 1;

        if (pad3 && !pad4)
            return false;

        if (i + 1 + !pad3 + !pad4 > outLen)
            return false;

        e1 = Base64_Char2Val_CT(e1);
        e2 = Base64_Char2Val_CT(e2);
        e3 = (uint8_t)((e3 == PAD) ? 0 : Base64_Char2Val_CT(e3));
        e4 = (uint8_t)((e4 == PAD) ? 0 : Base64_Char2Val_CT(e4));

        if (e1 == BAD || e2 == BAD || e3 == BAD || e4 == BAD)
            return false;

        b1 = (uint8_t)((e1 << 2) | (e2 >> 4));
        b2 = (uint8_t)(((e2 & 0xF) << 4) | (e3 >> 2));
        b3 = (uint8_t)(((e3 & 0x3) << 6) | e4);

        out[i++] = b1;
        if (!pad3)
            out[i++] = b2;
        if (!pad4)
            out[i++] = b3;
        else
            break;
    }

    return (outLen == i);
}

static const __attribute__((aligned(64))) uint8_t hexDecode[] =
{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
  BAD, BAD, BAD, BAD, BAD, BAD, BAD,
  10, 11, 12, 13, 14, 15,  /* upper case A-F */
  BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
  BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
  BAD, BAD, BAD, BAD, BAD, BAD, BAD, BAD,
  BAD, BAD,  /* G - ` */
  10, 11, 12, 13, 14, 15   /* lower case a-f */
};

bool wg_from_hex(uint8_t *out, size_t outLen, const char *in, size_t inLen)
{
    size_t inIdx  = 0;
    size_t outIdx = 0;

    if (in == NULL || out == NULL)
        return false;

    if (inLen % 2)
        return false;

    if (outLen != (inLen / 2))
        return false;

    while (inLen) {
        uint8_t b  = (uint8_t)(in[inIdx++] - BASE16_MIN);  /* 0 starts at 0x30 */
        uint8_t b2 = (uint8_t)(in[inIdx++] - BASE16_MIN);

        /* sanity checks */
        if (b >=  sizeof(hexDecode)/sizeof(hexDecode[0]))
            return false;
        if (b2 >= sizeof(hexDecode)/sizeof(hexDecode[0]))
            return false;

        b  = hexDecode[b];
        b2 = hexDecode[b2];

        if (b == BAD || b2 == BAD)
            return false;

        out[outIdx++] = (uint8_t)((b << 4) | b2);
        inLen -= 2;
    }

    return true;
}


static const __attribute__((aligned(64))) uint8_t hexEncode[] =
{ '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

bool wg_to_hex(char *out, size_t outLen, const uint8_t *in, size_t inLen)
{
    size_t outIdx = 0;
    size_t i;

    if (in == NULL || out == NULL)
        return false;

    if (outLen < inLen * 2)
        return false;

    for (i = 0; i < inLen; i++) {
        uint8_t hb = in[i] >> 4;
        uint8_t lb = in[i] & 0x0f;

        hb = hexEncode[hb];
        lb = hexEncode[lb];

        out[outIdx++] = hb;
        out[outIdx++] = lb;
    }

    /* If the output buffer has a room for an extra byte, add a null terminator */
    if (outLen > outIdx)
        out[outIdx]= '\0';

    return true;
}

#else /* !IPC_SUPPORTS_KERNEL_INTERFACE || NO_IPC_LLCRYPTO */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

bool wg_to_base64(char *base64, size_t base64_len, const uint8_t *raw, size_t raw_len) {
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

bool wg_from_base64(uint8_t *raw, size_t raw_len, const char *base64, size_t base64_len) {
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

bool wg_to_hex(char *hex, size_t hex_len, const uint8_t *raw, size_t raw_len) {
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

bool wg_from_hex(uint8_t *raw, size_t raw_len, const char *hex, size_t hex_len) {
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

#endif /* !IPC_SUPPORTS_KERNEL_INTERFACE || NO_IPC_LLCRYPTO */

bool wg_is_zero(const uint8_t *key, size_t key_len)
{
	volatile uint8_t acc = 0;

	for (unsigned int i = 0; i < key_len; ++i) {
		acc |= key[i];
		asm volatile("" : "=r"(acc) : "0"(acc));
	}
	return 1 & ((acc - 1) >> 8);
}
