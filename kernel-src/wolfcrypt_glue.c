// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2025 wolfSSL Inc. <info@wolfssl.com>
 */

#include <crypto/scatterwalk.h>
#include <linux/random.h>
#include "wolfcrypt_glue.h"

#if defined(WG_USE_PUBLIC_KEY_COMPRESSION) && !defined(HAVE_COMP_KEY)
	#error WG_USE_PUBLIC_KEY_COMPRESSION requires HAVE_COMP_KEY
#endif

int wc_hmac_oneshot_prealloc(struct Hmac *wc_hmac, const int type, byte *out, const size_t out_space, const byte *message,
		    const size_t message_len, const byte *key, const size_t key_len)
{
	int ret;

	ret = wc_HmacSizeByType(type);
	if (ret < 0)
            WC_DEBUG_PR_NEG_RET(ret);
	if (out_space < (size_t)ret) {
            WC_DEBUG_PR("out_space=%zu ret=%d\n", out_space, ret);
            WC_DEBUG_PR_NEG_RET(-ENOBUFS);
        }

	if ((key_len > UINT_MAX) || (message_len > UINT_MAX))
            WC_DEBUG_PR_NEG_RET(-EINVAL);

	ret = wc_HmacInit(wc_hmac, NULL /* heap */, INVALID_DEVID);
	if (ret == 0)
		ret = wc_HmacSetKey(wc_hmac, type, key, (word32)key_len);
	if (ret == 0)
		ret = wc_HmacUpdate(wc_hmac, message, (word32)message_len);
	if (ret == 0)
		ret = wc_HmacFinal(wc_hmac, out);

	wc_HmacFree(wc_hmac);

	WC_DEBUG_PR_NEG_RET(ret);
}

int wc_hmac_oneshot(const int type, byte *out, const size_t out_space, const byte *message,
		    const size_t message_len, const byte *key, const size_t key_len)
{
	/* sizeof(struct Hmac) is 832 if SHA3 is enabled. */
	struct Hmac *wc_hmac = (struct Hmac *)malloc(sizeof(*wc_hmac));
	int ret;

	if (! wc_hmac)
		WC_DEBUG_PR_NEG_RET(-ENOMEM);

	ret = wc_hmac_oneshot_prealloc(wc_hmac, type, out, out_space, message,
				       message_len, key, key_len);

	free(wc_hmac);
	WC_DEBUG_PR_NEG_RET(ret);
}

static const byte ZeroNonce[AES_IV_SIZE] = {};

int wc_AesGcm_Appended_Tag_Encrypt(Aes* aes, byte* out, word32 out_space,
                                   const byte* in, word32 in_sz,
                                   const byte* iv, word32 iv_sz,
                                   const byte* authIn, word32 authIn_sz,
                                   const word32 authTag_len)
{
	if (out_space - authTag_len < in_sz)
		WC_DEBUG_PR_NEG_RET(-ENOBUFS);

	if (! iv) {
		iv = ZeroNonce;
		iv_sz = sizeof(ZeroNonce);
	}

	WC_DEBUG_PR_NEG_RET(wc_AesGcmEncrypt(aes, out, in, in_sz, iv, iv_sz,
                                            out + in_sz, authTag_len,
                                            authIn, authIn_sz));
}

int wc_AesGcm_Appended_Tag_Decrypt(Aes* aes, byte* out, word32 out_space,
                                   const byte* in, word32 in_sz,
                                   const byte* iv, word32 iv_sz,
                                   const byte* authIn, word32 authIn_sz,
                                   const word32 authTag_len)
{
	if (in_sz < authTag_len)
		WC_DEBUG_PR_NEG_RET(-EINVAL);
	if (out_space < in_sz - authTag_len)
		WC_DEBUG_PR_NEG_RET(-ENOBUFS);

	if (! iv) {
		iv = ZeroNonce;
		iv_sz = sizeof(ZeroNonce);
	}

	WC_DEBUG_PR_NEG_RET(wc_AesGcmDecrypt(aes, out, in, in_sz - authTag_len, iv, iv_sz,
                                            in + in_sz - authTag_len, authTag_len,
                                            authIn, authIn_sz));
}

static __always_inline int wc_AesGcm_oneshot_crypt(byte* out, size_t out_space, const byte* key, size_t keySz, const byte* in, size_t inSz,
						   const byte* iv, size_t ivSz,
						   const byte* authIn, size_t authInSz,
                                                   size_t authTagSz,
						   int decrypt_p)
{
	int ret;
	Aes *aes;

	if ((out_space > UINT_MAX) ||
	    (keySz > UINT_MAX) ||
	    (inSz > UINT_MAX) ||
	    (ivSz > UINT_MAX) ||
	    (authInSz > UINT_MAX) ||
            (authTagSz > UINT_MAX))
	{
		WC_DEBUG_PR_NEG_RET(-EINVAL);
	}

	aes = (Aes *)malloc(sizeof(*aes));
	if (! aes)
		WC_DEBUG_PR_NEG_RET(-ENOMEM);

	ret = wc_AesInit(aes, NULL, INVALID_DEVID);
	if (ret != 0)
		goto out;

	ret = wc_AesGcmSetKey(aes, key, keySz);

	if (ret == 0) {
		if (decrypt_p)
			ret = wc_AesGcm_Appended_Tag_Decrypt(aes, out, out_space, in, inSz, iv, ivSz,
							     authIn, authInSz, authTagSz);
		else
			ret = wc_AesGcm_Appended_Tag_Encrypt(aes, out, out_space, in, inSz, iv, ivSz,
							     authIn, authInSz, authTagSz);
	}

        wc_AesFree(aes);

out:

	free(aes);
	WC_DEBUG_PR_NEG_RET(ret);
}

int wc_AesGcm_oneshot_encrypt(byte* out, size_t out_space, const byte* key, size_t keySz, const byte* in, size_t inSz,
                              const byte* iv, size_t ivSz,
                              const byte* authIn, size_t authInSz, size_t authTagSz)
{
    WC_DEBUG_PR_NEG_RET(wc_AesGcm_oneshot_crypt(out, out_space, key, keySz, in, inSz, iv, ivSz, authIn, authInSz, authTagSz, 0));
}

int wc_AesGcm_oneshot_decrypt(byte* out, size_t out_space, const byte* key, size_t keySz, const byte* in, size_t inSz,
			      const byte* iv, size_t ivSz,
			      const byte* authIn, size_t authInSz, size_t authTagSz)
{
    WC_DEBUG_PR_NEG_RET(wc_AesGcm_oneshot_crypt(out, out_space, key, keySz, in, inSz, iv, ivSz, authIn, authInSz, authTagSz, 1));
}

#ifdef WOLFSSL_AESGCM_STREAM

static __always_inline bool wc_AesGcm_crypt_sg_inplace(struct scatterlist *src, const size_t src_len,
						       const u8 *ad, const size_t ad_len,
						       u64 nonce,
						       const u8 *key, const size_t key_len,
						       int isDecrypt)
{
    int ret = -1;
    struct sg_mapping_iter miter;
    unsigned int flags;
    int sl;
    Aes *aes = NULL;
    byte full_nonce[AES_IV_SIZE];

    if (WARN_ON((src_len > UINT_MAX) ||
                (ad_len > UINT_MAX) ||
                (key_len > UINT_MAX)))
    {
        ret = -EINVAL;
        WC_DEBUG_PR_CODEPOINT();
        goto out;
    }

    aes = (Aes *)XMALLOC(sizeof *aes, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (! aes) {
        ret = -ENOMEM;
        WC_DEBUG_PR_CODEPOINT();
        goto out;
    }

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        ret = -EINVAL;
        WC_DEBUG_PR_CODEPOINT();
        goto out;
    }

    memset(full_nonce, 0, sizeof(full_nonce));
#ifdef BIG_ENDIAN_ORDER
    nonce = cpu_to_le64(nonce);
#endif
    memcpy(full_nonce + 4, (u8 *)&nonce, sizeof(nonce));

    if (isDecrypt)
        ret = wc_AesGcmDecryptInit(aes, key, (word32)key_len,
                                   full_nonce, (word32)sizeof(full_nonce));
    else
        ret = wc_AesGcmEncryptInit(aes, key, (word32)key_len,
                                   full_nonce, (word32)sizeof(full_nonce));
    if (ret != 0) {
        WC_DEBUG_PR_CODEPOINT();
        goto out;
    }

    if (ad) {
        if (isDecrypt)
            ret = wc_AesGcmDecryptUpdate(aes, NULL, NULL,
                                         0, ad, ad_len);
        else
            ret = wc_AesGcmEncryptUpdate(aes, NULL, NULL,
                                         0, ad, ad_len);
        if (ret != 0) {
            WC_DEBUG_PR_CODEPOINT();
            goto out;
        }
    }

    flags = SG_MITER_TO_SG;
    if (!preemptible())
        flags |= SG_MITER_ATOMIC;

    sg_miter_start(&miter, src, sg_nents(src), flags);

    for (sl = src_len; sl > 0 && sg_miter_next(&miter); sl -= miter.length) {
        size_t length = min_t(size_t, sl, miter.length);

        if (isDecrypt)
            ret = wc_AesGcmDecryptUpdate(aes, miter.addr, miter.addr,
                                         length, NULL, 0);
        else
            ret = wc_AesGcmEncryptUpdate(aes, miter.addr, miter.addr,
                                         length, NULL, 0);
        if (ret != 0) {
            WC_DEBUG_PR_CODEPOINT();
            goto out;
        }
    }

    /* the remaining length (sl) really will be conditionally negative after
     * iteration -- this is Jason Donenfeld's algorithm from
     * chacha20poly1305_crypt_sg_inplace() in Linux
     * lib/crypto/chacha20poly1305.c.
     */
    if (sl <= -WC_AES_BLOCK_SIZE) {
        if (isDecrypt)
            ret = wc_AesGcmDecryptFinal(aes, miter.addr + miter.length + sl, WC_AES_BLOCK_SIZE);
        else
            ret = wc_AesGcmEncryptFinal(aes, miter.addr + miter.length + sl, WC_AES_BLOCK_SIZE);
        if (ret < 0) {
            WC_DEBUG_PR_CODEPOINT();
            goto out;
        }
    }

    sg_miter_stop(&miter);

    if (sl > -WC_AES_BLOCK_SIZE) {
        byte AuthTagBuf[WC_AES_BLOCK_SIZE];

        if (isDecrypt) {
            scatterwalk_map_and_copy(AuthTagBuf, src, src_len,
                                     sizeof AuthTagBuf, 0 /* isEncrypt */);
            ret = wc_AesGcmDecryptFinal(aes, AuthTagBuf, WC_AES_BLOCK_SIZE);
            if (ret < 0)
                goto out;
        } else {
            ret = wc_AesGcmEncryptFinal(aes, AuthTagBuf, WC_AES_BLOCK_SIZE);
            if (ret < 0)
                goto out;
            scatterwalk_map_and_copy(AuthTagBuf, src, src_len,
                                     sizeof AuthTagBuf, 1 /* isEncrypt */);
        }
    }

    ret = 0;

  out:

    wc_AesFree(aes);
    free(aes);

    WC_DEBUG_PR_IF_NEG(ret);

    return ret == 0;
}

#else /* !WOLFSSL_AESGCM_STREAM */

static __always_inline bool wc_AesGcm_crypt_sg_inplace(struct scatterlist *src, const size_t src_len,
						       const u8 *ad, const size_t ad_len,
						       u64 nonce,
						       const u8 *key, const size_t key_len,
						       int isDecrypt)
{
    int ret = -1;
    struct sg_mapping_iter miter;
    unsigned int flags;
    Aes *aes = NULL;
    byte full_nonce[AES_IV_SIZE];

    if (WARN_ON((src_len > UINT_MAX) ||
                (ad_len > UINT_MAX) ||
                (key_len > UINT_MAX)))
    {
        ret = -EINVAL;
        WC_DEBUG_PR_CODEPOINT();
        goto out;
    }

    if (sg_nents(src) < 1) {
        ret = -EINVAL;
        WC_DEBUG_PR_CODEPOINT();
        goto out;
    }

    aes = (Aes *)XMALLOC(sizeof *aes, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (! aes) {
        WC_DEBUG_PR_FALSE_RET(false);
    }

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret != 0) {
        ret = -EINVAL;
        WC_DEBUG_PR_CODEPOINT();
        goto out;
    }

    memset(full_nonce, 0, sizeof(full_nonce));
#ifdef BIG_ENDIAN_ORDER
    nonce = cpu_to_le64(nonce);
#endif
    memcpy(full_nonce + 4, (u8 *)&nonce, sizeof(nonce));

    flags = SG_MITER_TO_SG;
    if (!preemptible())
        flags |= SG_MITER_ATOMIC;

    ret = wc_AesGcmSetKey(aes, key, (word32)key_len);
    if (ret) {
        ret = -EINVAL;
        WC_DEBUG_PR_CODEPOINT();
        goto out;
    }

    if (sg_nents(src) == 1) {
        size_t length;

        sg_miter_start(&miter, src, sg_nents(src), flags);
        if ((sg_nents(src) == 1) && (! sg_miter_next(&miter))) {
            sg_miter_stop(&miter);
            ret = -EINVAL;
            WC_DEBUG_PR_CODEPOINT();
            goto out;
        }

        if (miter.length < src_len + WC_AES_BLOCK_SIZE) {
            sg_miter_stop(&miter);
            goto copy_after_all;
        }

        length = min_t(size_t, src_len, miter.length);

        if (isDecrypt) {
            ret = wc_AesGcmDecrypt(aes, miter.addr,
                                   miter.addr, (word32)length,
                                   full_nonce, (word32)sizeof(full_nonce),
                                   miter.addr + length, WC_AES_BLOCK_SIZE,
                                   ad, (word32)ad_len);
        }
        else {
            ret = wc_AesGcmEncrypt(aes, miter.addr,
                                   miter.addr, (word32)length,
                                   full_nonce, (word32)sizeof(full_nonce),
                                   miter.addr + length, WC_AES_BLOCK_SIZE,
                                   ad, (word32)ad_len);
        }

        sg_miter_stop(&miter);

        goto out;
    }

    copy_after_all:
    {
        byte *buf = (byte *)XMALLOC(src_len + WC_AES_BLOCK_SIZE, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        if (! buf) {
            ret = -ENOMEM;
            WC_DEBUG_PR_CODEPOINT();
            goto out;
        }

        if (isDecrypt) {
            scatterwalk_map_and_copy(buf, src, 0, src_len + WC_AES_BLOCK_SIZE, 0);
            ret = wc_AesGcmDecrypt(aes, buf,
                                   buf, (word32)src_len,
                                   full_nonce, (word32)sizeof(full_nonce),
                                   buf + src_len, WC_AES_BLOCK_SIZE,
                                   ad, (word32)ad_len);
            if (ret == 0)
                scatterwalk_map_and_copy(buf, src, 0, src_len, 1);
        }
        else {
            scatterwalk_map_and_copy(buf, src, 0, src_len, 0);
            ret = wc_AesGcmEncrypt(aes, buf,
                                   buf, (word32)src_len,
                                   full_nonce, (word32)sizeof(full_nonce),
                                   buf + src_len, WC_AES_BLOCK_SIZE,
                                   ad, (word32)ad_len);
            if (ret == 0)
                scatterwalk_map_and_copy(buf, src, 0, src_len + WC_AES_BLOCK_SIZE, 1);
        }
        free(buf);
    }

  out:

    wc_AesFree(aes);
    free(aes);

    WC_DEBUG_PR_IF_NEG(ret);

    return ret == 0;
}

#endif /* !WOLFSSL_AESGCM_STREAM */

bool wc_AesGcm_encrypt_sg_inplace(struct scatterlist *src, size_t src_len,
                                  const u8 *ad, const size_t ad_len,
                                  const u64 nonce,
                                  const u8 *key,
                                  const size_t key_len)
{
    WC_DEBUG_PR_FALSE_RET(wc_AesGcm_crypt_sg_inplace(src, src_len, ad, ad_len,
                                                   nonce, key, key_len, 0));
}

bool wc_AesGcm_decrypt_sg_inplace(struct scatterlist *src, size_t src_len,
                                  const u8 *ad, const size_t ad_len,
                                  const u64 nonce,
                                  const u8 *key,
                                  const size_t key_len)
{
    WC_DEBUG_PR_FALSE_RET(wc_AesGcm_crypt_sg_inplace(src, src_len - WC_AES_BLOCK_SIZE,
                                                   ad, ad_len, nonce, key, key_len, 1));
}

int wc_ecc_make_keypair_exim(u8 *private, const size_t private_len,
                             u8 *public, const size_t public_len,
                             const int curve_id, int compressed)
{
        struct wc_rng_inst *rng = NULL;
        ecc_key *key = NULL;
        int key_inited = 0;
        int ret;

        if ((private_len > UINT_MAX) ||
            (public_len > UINT_MAX))
        {
            WC_DEBUG_PR_NEG_RET(BAD_FUNC_ARG);
        }

        key = (ecc_key *)malloc(sizeof(*key));
        if (! key) {
            ret = MEMORY_E;
            goto out;
        }
        ret = wc_ecc_init(key);
        if (ret)
            goto out;
        key_inited = 1;

        rng = get_drbg(&wc_wg_drbg);
        if (! rng) {
            ret = SYSLIB_FAILED_E;
            goto out;
        }

        ret = wc_ecc_make_key_ex(
            &rng->rng,
            0 /* keysize -- use curve_id to designate the curve. */,
            key,
            curve_id);
        if (ret)
            goto out;

        {
            word32 outLen = (word32)private_len;
            PRIVATE_KEY_UNLOCK();
            ret = wc_ecc_export_private_only(key, private, &outLen);
            PRIVATE_KEY_LOCK();
            if (ret)
                goto out;
            if (outLen != (word32)private_len) {
                ret = WC_KEY_SIZE_E;
                goto out;
            }
        }

        {
            word32 outLen = (word32)public_len;
            PRIVATE_KEY_UNLOCK();
#ifdef HAVE_COMP_KEY
            ret = wc_ecc_export_x963_ex(key, public, &outLen, compressed);
#else
            if (compressed)
                WC_DEBUG_PR_NEG_RET(BAD_FUNC_ARG);
            ret = wc_ecc_export_x963(key, public, &outLen);
#endif
            PRIVATE_KEY_LOCK();
            if (ret)
                goto out;
            if (outLen != (word32)public_len) {
                ret = WC_KEY_SIZE_E;
                goto out;
            }
        }

        ret = 0;

out:

        if (rng)
            put_drbg(rng);
        if (key) {
            if (key_inited)
                wc_ecc_free(key);
            free(key);
        }

        WC_DEBUG_PR_NEG_RET(ret);
}

int wc_ecc_private_to_public_exim(const u8 *private, const size_t private_len,
                                  u8 *public, const size_t public_len,
                                  const int curve_id, int compressed)
{
        ecc_key *key = NULL;
        int key_inited = 0;
        int ret;

        if ((private_len > UINT_MAX) ||
            (public_len > UINT_MAX))
        {
            WC_DEBUG_PR_NEG_RET(BAD_FUNC_ARG);
        }

        key = (ecc_key *)malloc(sizeof(*key));
        if (! key) {
            ret = MEMORY_E;
            goto out;
        }
        ret = wc_ecc_init(key);
        if (ret)
            goto out;
        key_inited = 1;

        ret = wc_ecc_import_private_key_ex(private, (word32)private_len,
                                           NULL, 0, key, curve_id);
        if (ret)
            goto out;

        {
            struct wc_rng_inst *rng = get_drbg(&wc_wg_drbg);
            if (! rng) {
                ret = SYSLIB_FAILED_E;
                goto out;
            }

            ret = wc_ecc_make_pub_ex(key, NULL /* pubOut */, &rng->rng);

            put_drbg(rng);
        }

        if (ret)
            goto out;

        {
            word32 outLen = (word32)public_len;
            PRIVATE_KEY_UNLOCK();
#ifdef HAVE_COMP_KEY
            ret = wc_ecc_export_x963_ex(key, public, &outLen, compressed);
#else
            if (compressed)
                WC_DEBUG_PR_NEG_RET(BAD_FUNC_ARG);
            ret = wc_ecc_export_x963(key, public, &outLen);
#endif
            PRIVATE_KEY_LOCK();
            if (ret)
                goto out;
            if (outLen != (word32)public_len) {
                ret = WC_KEY_SIZE_E;
                goto out;
            }
        }

out:

        if (key) {
            if (key_inited)
                wc_ecc_free(key);
            free(key);
        }

        WC_DEBUG_PR_NEG_RET(ret);
}


int wc_ecc_shared_secret_exim(u8 *secret, size_t secret_len,
                              const u8 *private, size_t private_len,
                              const u8 *public, size_t public_len,
                              int curve_id)
{
    ecc_key *privKey = NULL, *pubKey = NULL;
    int privKey_inited = 0, pubKey_inited = 0;
    int ret;
#ifdef ECC_TIMING_RESISTANT
    struct wc_rng_inst *rng = NULL;
#endif

    if ((secret_len > UINT_MAX) ||
        (private_len > UINT_MAX) ||
        (public_len > UINT_MAX))
    {
        WC_DEBUG_PR_NEG_RET(-EINVAL);
    }

    privKey = (ecc_key *)malloc(sizeof(*privKey));
    if (! privKey)
        goto out;

    pubKey = (ecc_key *)malloc(sizeof(*pubKey));
    if (! pubKey)
        goto out;

    ret = wc_ecc_init(privKey);
    if (ret != 0)
        goto out;
    privKey_inited = 1;

    ret = wc_ecc_init(pubKey);
    if (ret != 0)
        goto out;
    pubKey_inited = 1;

#ifdef ECC_TIMING_RESISTANT
    rng = get_drbg(&wc_wg_drbg);
    if (! rng) {
        ret = -EFAULT;
        goto out;
    }
    ret = wc_ecc_set_rng(privKey, &rng->rng);
    if (ret != 0)
        goto out;
#endif

    ret = wc_ecc_import_private_key_ex(private, (word32)private_len,
                                       NULL, 0, privKey, curve_id);
    if (ret != 0)
        goto out;

    ret = wc_ecc_import_x963_ex(public, (word32)public_len, pubKey, curve_id);
    if (ret != 0)
        goto out;

    {
        word32 secret_len_copy = (word32)secret_len;
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_shared_secret(privKey, pubKey, secret, &secret_len_copy);
        PRIVATE_KEY_LOCK();
        if ((ret == 0) && (secret_len_copy != (word32)secret_len))
            ret = WC_KEY_SIZE_E;
    }

out:

#ifdef ECC_TIMING_RESISTANT
        if (rng)
            put_drbg(rng);
#endif

        if (privKey) {
            if (privKey_inited)
                wc_ecc_free(privKey);
            free(privKey);
        }
        if (pubKey) {
            if (pubKey_inited)
                wc_ecc_free(pubKey);
            free(pubKey);
        }

	WC_DEBUG_PR_NEG_RET(ret);
}

/* snarfed from wolfssl/linuxkm/lkcapi_sha_glue.c */
struct wc_linuxkm_drbg_ctx wc_wg_drbg;

void wc_linuxkm_drbg_ctx_clear(struct wc_linuxkm_drbg_ctx * ctx)
{
    unsigned int i;

    if (ctx->rngs) {
        for (i = 0; i < ctx->n_rngs; ++i) {
            if (ctx->rngs[i].lock != 0) {
                /* better to leak than to crash. */
                pr_err("BUG: wc_linuxkm_drbg_ctx_clear called with DRBG #%d still locked.", i);
                ctx->rngs = NULL;
                ctx->n_rngs = 0;
                return;
            }
            else
                wc_FreeRng(&ctx->rngs[i].rng);
        }
        free(ctx->rngs);
        ctx->rngs = NULL;
        ctx->n_rngs = 0;
    }

    return;
}

int wc_linuxkm_drbg_init_ctx(struct wc_linuxkm_drbg_ctx *ctx)
{
    unsigned int i;
    int ret;
    int need_reenable_vec;
    int can_sleep = (preempt_count() == 0);

    ctx->n_rngs = max(4, (int)nr_cpu_ids);
    ctx->rngs = (struct wc_rng_inst *)malloc(sizeof(*ctx->rngs) * ctx->n_rngs);
    if (! ctx->rngs) {
        ctx->n_rngs = 0;
        WC_DEBUG_PR_NEG_RET(-ENOMEM);
    }
    XMEMSET(ctx->rngs, 0, sizeof(*ctx->rngs) * ctx->n_rngs);

    for (i = 0; i < ctx->n_rngs; ++i) {
        ctx->rngs[i].lock = 0;
	need_reenable_vec = (DISABLE_VECTOR_REGISTERS() == 0);
        ret = wc_InitRng(&ctx->rngs[i].rng);
        if (ret == 0)
            ret = wc_RNG_GenerateBlock(&ctx->rngs[i].rng, ctx->rngs[i].rnd_pool, sizeof(ctx->rngs[i].rnd_pool));
        if (need_reenable_vec)
            REENABLE_VECTOR_REGISTERS();
        if (ret != 0) {
            pr_warn_once("WARNING: wc_linuxkm_drbg_init_ctx: wc_InitRng/wc_RNG_GenerateBlock returned %d\n",ret);
            ret = -EINVAL;
            break;
        }
        if (can_sleep)
            cond_resched();
    }

    if (ret != 0) {
        wc_linuxkm_drbg_ctx_clear(ctx);
    }

    WC_DEBUG_PR_NEG_RET(ret);
}

/* get_drbg() uses atomic operations to get exclusive ownership of a DRBG
 * without delay.  It expects to be called in uninterruptible context, though
 * works fine in any context.  It starts by trying the DRBG matching the current
 * CPU ID, and if that doesn't immediately succeed, it iterates upward until one
 * succeeds.  The first attempt will always succeed, even under intense load,
 * unless there is or has recently been a reseed or mix-in operation competing
 * with generators.
 *
 * Note that wc_linuxkm_drbg_init_ctx() allocates at least 4 DRBGs, regardless
 * of nominal core count, to avoid stalling generators on unicore targets.
 *
 * Note also, vector ops are always disabled while a DRBG is checked out, to be
 * sure no vectorized function pointers will be cached making the DRBG unusable
 * from vector-unsafe contexts.
 */

struct wc_rng_inst *get_drbg(struct wc_linuxkm_drbg_ctx *ctx) {
    int n, new_lock_value;

    if (! ctx->rngs) {
        pr_err("BUG: get_drbg() called before wc_linuxkm_drbg_init_ctx().");
        return NULL;
    }

    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    if (1) {
        migrate_disable();
        new_lock_value = 2;
    }
    else
    #endif
    {
        new_lock_value = 1;
    }

    n = raw_smp_processor_id();

    for (;;) {
        int expected = 0;
        if (likely(__atomic_compare_exchange_n(&ctx->rngs[n].lock, &expected, new_lock_value, 0, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE))) {
            struct wc_rng_inst *drbg = &ctx->rngs[n];
            drbg->disabled_vec_ops = (DISABLE_VECTOR_REGISTERS() == 0);
            return drbg;
        }
        ++n;
        if (n >= (int)ctx->n_rngs)
            n = 0;
        cpu_relax();
    }

    __builtin_unreachable();
}

/* get_drbg_n() is used by bulk seed, mix-in, and reseed operations.  It expects
 * the caller to be able to wait until the requested DRBG is available.
 */
struct wc_rng_inst *get_drbg_n(struct wc_linuxkm_drbg_ctx *ctx, int n) {
    int can_sleep = (preempt_count() == 0);

    for (;;) {
        int expected = 0;
        if (likely(__atomic_compare_exchange_n(&ctx->rngs[n].lock, &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE))) {
            struct wc_rng_inst *drbg = &ctx->rngs[n];
            drbg->disabled_vec_ops = 0;
            return drbg;
        }
        if (can_sleep) {
            if (signal_pending(current))
                return NULL;
            cond_resched();
        }
        else
            cpu_relax();
    }

    __builtin_unreachable();
}

void put_drbg(struct wc_rng_inst *drbg) {
    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    int migration_disabled = (drbg->lock == 2);
    #endif
    if (drbg->disabled_vec_ops) {
        REENABLE_VECTOR_REGISTERS();
        drbg->disabled_vec_ops = 0;
    }
    __atomic_store_n(&(drbg->lock),0,__ATOMIC_RELEASE);
    #if defined(CONFIG_SMP) && !defined(CONFIG_PREEMPT_COUNT) && \
        (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
    if (migration_disabled)
        migrate_enable();
    #endif
}

int wc_linuxkm_drbg_generate(struct wc_linuxkm_drbg_ctx *ctx,
                             const u8 *src, unsigned int slen,
                             u8 *dst, unsigned int dlen,
                             int nofail_p)
{
    int ret, retried = 0;
    int need_put_drbg = 0;
    struct wc_rng_inst *drbg = get_drbg(ctx);

    if (! drbg) {
        pr_err_once("BUG: get_drbg() failed.");
        ret = -EFAULT;
        goto out;
    }
    need_put_drbg = 1;

    if ((src == NULL) && (dlen <= 8) && ((size_t)drbg->rnd_pool_offset <= sizeof(drbg->rnd_pool) - (size_t)dlen)) {
        XMEMCPY(dst, drbg->rnd_pool + drbg->rnd_pool_offset, dlen);
        wc_ForceZero(drbg->rnd_pool + drbg->rnd_pool_offset, dlen);
        drbg->rnd_pool_offset += dlen;
        put_drbg(drbg);
        return 0;
    }

retry:

#if defined(HAVE_FIPS) && FIPS_VERSION_LT(6,0)
    (void)src;
    (void)slen;
#else
    if (slen > 0) {
        ret = wc_RNG_DRBG_Reseed(&drbg->rng, src, slen);
        if (ret != 0) {
            pr_warn_once("WARNING: wc_RNG_DRBG_Reseed returned %d.\n",ret);
            ret = -EINVAL;
            goto out;
        }
    }
#endif

    if (dlen <= 8) {
        ret = wc_RNG_GenerateBlock(&drbg->rng, drbg->rnd_pool, (word32)sizeof(drbg->rnd_pool));
        if (ret == 0) {
            memcpy(dst, drbg->rnd_pool, dlen);
            wc_ForceZero(drbg->rnd_pool, dlen);
            drbg->rnd_pool_offset = dlen;
            goto out;
        }
    }
    else {
        ret = wc_RNG_GenerateBlock(&drbg->rng, dst, dlen);
    }

    if (unlikely(ret == WC_NO_ERR_TRACE(RNG_FAILURE_E)) && (! retried)) {
        word32 cur_rng_status = (word32)drbg->rng.status;
        int need_reenable_vec;
        retried = 1;
        wc_FreeRng(&drbg->rng);
        need_reenable_vec = (DISABLE_VECTOR_REGISTERS() == 0);
        ret = wc_InitRng(&drbg->rng);
        if (ret == 0) {
            pr_warn("WARNING: reinitialized DRBG #%d after RNG_FAILURE_E with status %u.", raw_smp_processor_id(), cur_rng_status);
            goto retry;
        }
        else {
            pr_warn_once("ERROR: reinitialization of DRBG #%d after RNG_FAILURE_E with status %u failed with ret %d.", raw_smp_processor_id(), cur_rng_status, ret);
            ret = -EINVAL;
        }
    }
    else if (ret != 0) {
        pr_warn_once("WARNING: wc_RNG_GenerateBlock returned %d\n",ret);
        ret = -EINVAL;
    }

out:

    if (need_put_drbg)
        put_drbg(drbg);

    if ((ret == 0) || (! nofail_p))
        WC_DEBUG_PR_NEG_RET(ret);

    pr_warn_once("WARNING: wc_linuxkm_drbg_generate() failed with code %d -- using fallback to get_random_bytes().\n", ret);
    get_random_bytes(dst, dlen);

    return 0;
}

#if !defined(HAVE_FIPS) || FIPS_VERSION_GE(6,0)
int wc_linuxkm_drbg_seed(struct wc_linuxkm_drbg_ctx *ctx,
                        const u8 *seed, unsigned int slen)
{
    u8 *seed_copy = NULL;
    int ret;
    int n;

    if (slen == 0)
        return 0;

    seed_copy = (u8 *)malloc(slen + 2);
    if (! seed_copy)
        WC_DEBUG_PR_NEG_RET(-ENOMEM);
    XMEMCPY(seed_copy + 2, seed, slen);

    /* this iteration counts down, whereas the iteration in get_drbg() counts
     * up, to assure they can't possibly phase-lock to each other.
     */
    for (n = ctx->n_rngs - 1; n >= 0; --n) {
        struct wc_rng_inst *drbg = get_drbg_n(ctx, n);

        if (! drbg) {
            ret = -EINTR;
            break;
        }

        /* perturb the seed with the CPU ID, so that no DRBG has the exact same
         * seed.
         */
        seed_copy[0] = (u8)(n >> 8);
        seed_copy[1] = (u8)n;

        {
            /* for the default RNG, make sure we don't cache an underlying SHA256
             * method that uses vector insns (forbidden from irq handlers).
             */
            int need_fpu_restore = (DISABLE_VECTOR_REGISTERS() == 0);
            ret = wc_RNG_DRBG_Reseed(&drbg->rng, seed_copy, slen + 2);
            if (need_fpu_restore)
                REENABLE_VECTOR_REGISTERS();
        }

        if (ret != 0) {
            pr_warn_once("WARNING: wc_RNG_DRBG_Reseed returned %d\n",ret);
            ret = -EINVAL;
        }

        put_drbg(drbg);

        if (ret != 0)
            break;
    }

    free(seed_copy);

    WC_DEBUG_PR_NEG_RET(ret);
}
#endif
