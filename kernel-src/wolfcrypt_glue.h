// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2025 wolfSSL Inc. <info@wolfssl.com>
 */

#ifndef WOLFCRYPTO_SHIM_H
#define WOLFCRYPTO_SHIM_H

#include <wolfssl/options.h>

#if !defined(HAVE_AESGCM) || (!defined(HAVE_AESGCM_DECRYPT) && defined(NO_AES_DECRYPT))
    #error libwolfssl missing AES-GCM with streaming
#endif
#if defined(NO_SHA256)
    #error libwolfssl missing SHA256
#endif
#if defined(NO_HMAC)
    #error libwolfssl missing HMAC
#endif
#if !defined(HAVE_ECC)
    #error libwolfssl missing ECC
#endif

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#ifndef WOLFSSL_LINUXKM
    #error libwolfssl configured without --enable-linuxkm
#endif

/* internal file misc.c at commit d9f7629296 has inline CopyString() that calls
 * XMALLOC().
 */
#include <linux/mm.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if 0
#define WOLFSSL_MISC_INCLUDED
#undef min
#undef max
#include <wolfcrypt/src/misc.c>
#endif

#include <linux/kconfig.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>

#define PRNT_NZ(...)                                                    \
    ({                                                                  \
        int _ret = (__VA_ARGS__);                                       \
        if (_ret) {                                                     \
            printk(KERN_NOTICE "%s@%d: %d\n", __FILE__, __LINE__, _ret); \
        }                                                               \
        _ret;                                                           \
    })

#ifdef DEBUG
#define DBG_PRNT_NZ(...) PRNT_NZ(__VA_ARGS__)
#else
#define DBG_PRNT_NZ(...) (__VA_ARGS__)
#endif

#if defined(DEBUG) || defined(WOLFCRYPT_GLUE_DEBUG)

#define WC_DEBUG_PR_IF_NEG(x) do { typeof(x) _ret = (x); if (_ret < 0) { pr_notice("value is %ld at %s %s L %d\n", (long int)_ret, __FILE__, __FUNCTION__, __LINE__); dump_stack(); } } while (0)
#define WC_DEBUG_PR_NEG_RET(x) do { typeof(x) _ret = (x); if (_ret < 0) { pr_notice("returning %ld from %s %s L %d\n", (long int)_ret, __FILE__, __FUNCTION__, __LINE__); dump_stack(); } return _ret; } while (0)
#define WC_DEBUG_PR_FALSE_RET(x) do { typeof(x) _ret = (x); if (! _ret) { pr_notice("returning false from %s %s L %d\n", __FILE__, __FUNCTION__, __LINE__); dump_stack(); } return _ret; } while (0)
#define WC_DEBUG_PR_NULL_RET(x) do { typeof(x) _ret = (x); if (! _ret) { pr_notice("value is NULL at %s %s L %d\n", __FILE__, __FUNCTION__, __LINE__); dump_stack(); } return _ret; } while (0)
#define WC_DEBUG_PR_VOID_RET do { pr_notice("return at %s %s L %d\n", __FILE__, __FUNCTION__, __LINE__); dump_stack(); return; } while (0)
#define WC_DEBUG_PR_CODEPOINT() pr_notice("codepoint at %s %s L %d\n", __FILE__, __FUNCTION__, __LINE__)
#define WC_DEBUG_PR(fmt, ...) pr_notice("%s %s L %d: " fmt, __FILE__, __FUNCTION__, __LINE__, ## __VA_ARGS__)

#else

#define WC_DEBUG_PR_IF_NEG(x) WC_DO_NOTHING
#define WC_DEBUG_PR_NEG_RET(x) return(x)
#define WC_DEBUG_PR_FALSE_RET(x) return(x)
#define WC_DEBUG_PR_NULL_RET(x) return(x)
#define WC_DEBUG_PR_VOID_RET return
#define WC_DEBUG_PR_CODEPOINT() WC_DO_NOTHING
#define WC_DEBUG_PR(fmt, ...) WC_DO_NOTHING

#endif

static inline int ConstantCompare(const byte* a, const byte* b,
                                             int length)
{
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ b[i];
    }

    return compareSum;
}

extern int wc_hmac_oneshot_prealloc(struct Hmac *wc_hmac, const int type, byte *out, const size_t out_space, const byte *message,
                                    const size_t message_len, const byte *key, const size_t key_len);

extern int wc_hmac_oneshot(int type, byte *out, const size_t out_space, const byte *message,
		    const size_t message_len, const byte *key, const size_t key_len);

static inline int wc_sha256_oneshot(byte *out, const byte *message, const size_t message_len)
{
	int ret;
	wc_Sha256 sha;

	if (message_len > UINT_MAX)
		return -EINVAL;

	ret = wc_InitSha256(&sha);
	if (ret == 0)
		ret = wc_Sha256Update(&sha, message, (word32)message_len);
	if (ret == 0)
		ret = wc_Sha256Final(&sha, out);

        wc_Sha256Free(&sha);

	return ret;
}

static inline int wc_sha256_oneshot2(byte *out, const byte *message1, const size_t message1_len, const byte *message2, const size_t message2_len)
{
	int ret;
	wc_Sha256 sha;

	if ((message1_len > UINT_MAX) || (message2_len > UINT_MAX))
		return -EINVAL;

	ret = wc_InitSha256(&sha);
	if (ret == 0)
		ret = wc_Sha256Update(&sha, message1, (word32)message1_len);
	if (ret == 0)
		ret = wc_Sha256Update(&sha, message2, (word32)message2_len);
	if (ret == 0)
		ret = wc_Sha256Final(&sha, out);

        wc_Sha256Free(&sha);

	return ret;
}

static inline u64 wc_u64_keyed_hash(const byte *key, const size_t key_len, const byte *message, const size_t message_len) {
    u64 ret[WC_SHA256_DIGEST_SIZE / sizeof(u64)];
    if (wc_sha256_oneshot2((byte *)ret, key, key_len, message, (word32)message_len) < 0)
        return ~0UL;
    else
        return ret[0];
}

static inline u32 wc_u32_keyed_hash(const byte *key, const size_t key_len, const byte *message, const size_t message_len) {
    u32 ret[WC_SHA256_DIGEST_SIZE / sizeof(u32)];
    if (wc_sha256_oneshot2((byte *)ret, key, key_len, message, (word32)message_len) < 0)
        return ~0U;
    else
        return ret[0];
}

static inline u32 wc_2u32_keyed_hash(const byte *key, const size_t key_len, u32 u1, u32 u2) {
    struct __attribute__((packed)) {
        u32 u1;
        u32 u2;
    } ubuf = { .u1 = u1, .u2 = u2 };
    return wc_u32_keyed_hash(key, key_len, (byte *)&ubuf, sizeof(ubuf));
}

static inline u32 wc_3u32_keyed_hash(const byte *key, const size_t key_len, u32 u1, u32 u2, u32 u3) {
    struct __attribute__((packed)) {
        u32 u1;
        u32 u2;
        u32 u3;
    } ubuf = { .u1 = u1, .u2 = u2, .u3 = u3 };
    return wc_u32_keyed_hash(key, key_len, (byte *)&ubuf, sizeof(ubuf));
}

extern int wc_AesGcm_Appended_Tag_Encrypt(Aes* aes, byte* out, word32 out_space,
                                          const byte* in, word32 in_sz,
                                          const byte* iv, word32 iv_sz,
                                          const byte* authIn, word32 authIn_sz,
                                          const word32 authtag_len);

extern int wc_AesGcm_Appended_Tag_Decrypt(Aes* aes, byte* out, word32 out_space,
                                          const byte* in, word32 in_sz,
                                          const byte* iv, word32 iv_sz,
                                          const byte* authIn, word32 authIn_sz,
                                          const word32 authtag_len);

extern int wc_AesGcm_oneshot_encrypt(byte* out, size_t out_space, const byte* key, size_t keySz, const byte* in, size_t inSz,
                   const byte* iv, size_t ivSz,
                   const byte* authIn, size_t authInSz, size_t authTagSz);

extern int wc_AesGcm_oneshot_decrypt(byte* out, size_t out_space, const byte* key, size_t keySz, const byte* in, size_t inSz,
                   const byte* iv, size_t ivSz,
                   const byte* authIn, size_t authInSz, size_t authTagSz);

extern bool wc_AesGcm_encrypt_sg_inplace(struct scatterlist *src, size_t src_len,
                                         const u8 *ad, const size_t ad_len,
                                         const u64 nonce,
                                         const u8 *key,
                                         const size_t key_len);

extern bool wc_AesGcm_decrypt_sg_inplace(struct scatterlist *src, size_t src_len,
                                         const u8 *ad, const size_t ad_len,
                                         const u64 nonce,
                                         const u8 *key,
                                         const size_t key_len);

/* snarfed from wolfssl/linuxkm/lkcapi_sha_glue.c */
struct wc_linuxkm_drbg_ctx {
    size_t n_rngs;
    struct wc_rng_inst {
        wolfSSL_Atomic_Int lock;
        WC_RNG rng;
        byte rnd_pool[1024];
        word32 rnd_pool_offset;
        int disabled_vec_ops;
    } *rngs; /* one per CPU ID */
};
extern struct wc_linuxkm_drbg_ctx wc_wg_drbg;
int wc_linuxkm_drbg_init_ctx(struct wc_linuxkm_drbg_ctx *ctx);
void wc_linuxkm_drbg_ctx_clear(struct wc_linuxkm_drbg_ctx * ctx);
struct wc_rng_inst *get_drbg(struct wc_linuxkm_drbg_ctx *ctx);
struct wc_rng_inst *get_drbg_n(struct wc_linuxkm_drbg_ctx *ctx, int n);
void put_drbg(struct wc_rng_inst *drbg);
int wc_linuxkm_drbg_generate(struct wc_linuxkm_drbg_ctx *ctx,
                             const u8 *src, unsigned int slen,
                             u8 *dst, unsigned int dlen,
                             int nofail_p);
int wc_linuxkm_drbg_seed(struct wc_linuxkm_drbg_ctx *ctx,
                         const u8 *seed, unsigned int slen);

int wc_ecc_make_keypair_exim(u8 *private, const size_t private_len,
                             u8 *public, const size_t public_len,
                             const int curve_id, int compressed);

int wc_ecc_private_to_public_exim(const u8 *private, const size_t private_len,
                                  u8 *public, const size_t public_len,
                                  const int curve_id, int compressed);

int wc_ecc_shared_secret_exim(u8 *secret, size_t secret_len,
                              const u8 *private, size_t private_len,
                              const u8 *public, size_t public_len,
                              int curve_id);

/* with wc_get_random_bytes(), retval of 0 confirms wolfCrypt DRBG succeeded in
 * fulfilling the call, else failure.
 */
static inline WARN_UNUSED_RESULT int wc_get_random_bytes(u8 *dst, unsigned int dlen) {
    return wc_linuxkm_drbg_generate(&wc_wg_drbg, NULL, 0, dst, dlen, 0);
}

/* with wc_get_random_bytes_nofail(), non-wolfCrypt PRNG is used as fallback to
 * assure call is unconditionally fulfilled.
 */
static inline void wc_get_random_bytes_nofail(u8 *dst, unsigned int dlen) {
    (void)wc_linuxkm_drbg_generate(&wc_wg_drbg, NULL, 0, dst, dlen, 1);
}

/* Note these wrappers fall back to native get_random_bytes() if
 * wc_linuxkm_drbg_generate() fails for any reason.  The values returned by
 * wc_get_random_u*() are used only for internal purposes, never in
 * security-critical contexts, and are expected to succeed unconditionally.  Our
 * wc_linuxkm_drbg_generate() cannot succeed unconditionally, but native
 * get_random_bytes() does.
 */
#define IMPLEMENT_RANDOM_WORD_GENERATOR(type)                           \
    static inline type wc_get_random_ ## type (void) {                  \
        type ret;                                                       \
        wc_linuxkm_drbg_generate(&wc_wg_drbg, NULL, 0, (u8 *)&ret, (word32)sizeof(ret), 1); \
        return ret;                                                     \
    }                                                                   \
    struct swallow_the_semicolon

IMPLEMENT_RANDOM_WORD_GENERATOR(u8);
IMPLEMENT_RANDOM_WORD_GENERATOR(u16);
IMPLEMENT_RANDOM_WORD_GENERATOR(u32);
IMPLEMENT_RANDOM_WORD_GENERATOR(u64);

/* adapted from __get_random_u32_below() in drivers/char/random.c and
 * get_random_u32_below() in include/linux/random.h.
 */
static inline word32 wc_get_random_u32_below(u32 ceil) {
    BUILD_BUG_ON_MSG(!ceil, "wc_get_random_u32_below() must take ceil > 0");
    if (ceil <= 1)
        return 0;

    if (__builtin_constant_p(ceil)) {
        for (;;) {
                if (ceil <= 1U << 8) {
                        u32 mult = ceil * wc_get_random_u8();
                        if (likely(is_power_of_2(ceil) || (u8)mult >= (1U << 8) % ceil))
                                return mult >> 8;
                } else if (ceil <= 1U << 16) {
                        u32 mult = ceil * wc_get_random_u16();
                        if (likely(is_power_of_2(ceil) || (u16)mult >= (1U << 16) % ceil))
                                return mult >> 16;
                } else {
                        u64 mult = (u64)ceil * wc_get_random_u32();
                        if (likely(is_power_of_2(ceil) || (u32)mult >= -ceil % ceil))
                                return mult >> 32;
                }
        }
    }
    else {
        u64 mult = (u64)ceil * wc_get_random_u32();

        if (unlikely((u32)mult < ceil)) {
            u32 bound = -ceil % ceil;
            while (unlikely((u32)mult < bound))
                mult = (u64)ceil * wc_get_random_u32();
        }

        return mult >> 32;
    }
}

#endif /* WOLFCRYPTO_SHIM_H */
