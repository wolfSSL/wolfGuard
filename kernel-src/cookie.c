// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * Portions Copyright (C) 2020-2025 wolfSSL Inc. <info@wolfssl.com>
 */

#include "cookie.h"
#include "peer.h"
#include "device.h"
#include "messages.h"
#include "ratelimiter.h"
#include "timers.h"

#include <net/ipv6.h>
#include <crypto/algapi.h>

int wg_cookie_checker_init(struct cookie_checker *checker,
			    struct wg_device *wg)
{
	int ret = wc_get_random_bytes(checker->secret, NOISE_HASH_LEN);
	if (ret)
		return ret;
	init_rwsem(&checker->secret_lock);
	checker->secret_birthdate = ktime_get_coarse_boottime_ns();
	checker->device = wg;
	return 0;
}

enum { COOKIE_KEY_LABEL_LEN = 8 };
static const u8 mac1_key_label[COOKIE_KEY_LABEL_LEN] = "mac1----";
static const u8 cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";

static int precompute_key(u8 key[NOISE_SYMMETRIC_KEY_LEN],
			   const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
			   const u8 label[COOKIE_KEY_LABEL_LEN])
{
	return wc_sha256_oneshot2(key, label, COOKIE_KEY_LABEL_LEN, pubkey, NOISE_PUBLIC_KEY_LEN);
}

/* Must hold peer->handshake.static_identity->lock */
int wg_cookie_checker_precompute_device_keys(struct cookie_checker *checker)
{
	int ret;
	if (likely(checker->device->static_identity.has_identity)) {
		ret = precompute_key(checker->cookie_encryption_key,
			       checker->device->static_identity.static_public,
			       cookie_key_label);
		if (ret)
			return ret;
		ret = precompute_key(checker->message_mac1_key,
			       checker->device->static_identity.static_public,
			       mac1_key_label);
		if (ret)
			return ret;
	} else {
		memset(checker->cookie_encryption_key, 0,
		       NOISE_SYMMETRIC_KEY_LEN);
		memset(checker->message_mac1_key, 0, NOISE_SYMMETRIC_KEY_LEN);
		return 0;
	}
	__builtin_unreachable();
}

int wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer)
{
	int ret;
	ret = precompute_key(peer->latest_cookie.cookie_decryption_key,
		       peer->handshake.remote_static, cookie_key_label);
	if (ret)
		return ret;
	ret = precompute_key(peer->latest_cookie.message_mac1_key,
		       peer->handshake.remote_static, mac1_key_label);
	return ret;
}

void wg_cookie_init(struct cookie *cookie)
{
	memset(cookie, 0, sizeof(*cookie));
	init_rwsem(&cookie->lock);
}

static int compute_mac1(u8 mac1[COOKIE_LEN], const void *message, size_t len,
			 const u8 key[NOISE_SYMMETRIC_KEY_LEN])
{
	len = len - sizeof(struct message_macs) +
	      offsetof(struct message_macs, mac1);
	return wc_hmac_oneshot(WC_SHA256, mac1, COOKIE_LEN, message, len, key,
			       NOISE_SYMMETRIC_KEY_LEN);
}

static int compute_mac2(u8 mac2[COOKIE_LEN], const void *message, size_t len,
			 const u8 cookie[COOKIE_LEN])
{
	len = len - sizeof(struct message_macs) +
	      offsetof(struct message_macs, mac2);
	return wc_sha256_oneshot(mac2, message, len);
}

static int make_cookie(u8 cookie[COOKIE_LEN], struct sk_buff *skb,
			struct cookie_checker *checker)
{
	int ret;
	struct Hmac *wc_hmac; /* sizeof(struct Hmac) is 832 if SHA3 is enabled. */

	wc_hmac = (struct Hmac *)malloc(sizeof(*wc_hmac));
	if (! wc_hmac)
		return -ENOMEM;

	ret = wc_HmacInit(wc_hmac, NULL /* heap */, INVALID_DEVID);

	if ((ret == 0) && wg_birthdate_has_expired(checker->secret_birthdate,
				     COOKIE_SECRET_MAX_AGE)) {
		down_write(&checker->secret_lock);
		checker->secret_birthdate = ktime_get_coarse_boottime_ns();
		ret = wc_get_random_bytes(checker->secret, NOISE_HASH_LEN);
		up_write(&checker->secret_lock);
	}

	if (ret == 0) {
		down_read(&checker->secret_lock);

		ret = wc_HmacSetKey(wc_hmac, WC_SHA256, checker->secret, NOISE_HASH_LEN);

		if ((ret == 0) && (skb->protocol == htons(ETH_P_IP)))
			ret = wc_HmacUpdate(wc_hmac, (u8 *)&ip_hdr(skb)->saddr,
					    (word32)sizeof(struct in_addr));
		else if ((ret == 0) && (skb->protocol == htons(ETH_P_IPV6)))
			ret = wc_HmacUpdate(wc_hmac, (u8 *)&ipv6_hdr(skb)->saddr,
					    (word32)sizeof(struct in6_addr));
	
		if (ret == 0)
			ret = wc_HmacUpdate(wc_hmac, (u8 *)&udp_hdr(skb)->source, sizeof(__be16));

		if (ret == 0)
			ret = wc_HmacFinal(wc_hmac, cookie);

		up_read(&checker->secret_lock);
	}

	wc_HmacFree(wc_hmac);

	free(wc_hmac);

	return ret;
}

enum cookie_mac_state wg_cookie_validate_packet(struct cookie_checker *checker,
						struct sk_buff *skb,
						bool check_cookie)
{
	struct message_macs *macs = (struct message_macs *)
		(skb->data + skb->len - sizeof(*macs));
	enum cookie_mac_state ret;
	u8 computed_mac[COOKIE_LEN];
	u8 cookie[COOKIE_LEN];

	ret = INVALID_MAC;
	compute_mac1(computed_mac, skb->data, skb->len,
		     checker->message_mac1_key);
	if (ConstantCompare(computed_mac, macs->mac1, COOKIE_LEN))
		goto out;

	ret = VALID_MAC_BUT_NO_COOKIE;

	if (!check_cookie)
		goto out;

	if (make_cookie(cookie, skb, checker) != 0)
		goto out;

	compute_mac2(computed_mac, skb->data, skb->len, cookie);
	if (ConstantCompare(computed_mac, macs->mac2, COOKIE_LEN))
		goto out;

	ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
	if (!wg_ratelimiter_allow(skb, dev_net(checker->device->dev)))
		goto out;

	ret = VALID_MAC_WITH_COOKIE;

out:
	return ret;
}

void wg_cookie_add_mac_to_packet(void *message, size_t len,
				 struct wg_peer *peer)
{
	struct message_macs *macs = (struct message_macs *)
		((u8 *)message + len - sizeof(*macs));

	down_write(&peer->latest_cookie.lock);
	compute_mac1(macs->mac1, message, len,
		     peer->latest_cookie.message_mac1_key);
	memcpy(peer->latest_cookie.last_mac1_sent, macs->mac1, COOKIE_LEN);
	peer->latest_cookie.have_sent_mac1 = true;
	up_write(&peer->latest_cookie.lock);

	down_read(&peer->latest_cookie.lock);
	if (peer->latest_cookie.is_valid &&
	    !wg_birthdate_has_expired(peer->latest_cookie.birthdate,
				COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
		compute_mac2(macs->mac2, message, len,
			     peer->latest_cookie.cookie);
	else
		memset(macs->mac2, 0, COOKIE_LEN);
	up_read(&peer->latest_cookie.lock);
}

int wg_cookie_message_create(struct message_handshake_cookie *dst,
			      struct sk_buff *skb, __le32 index,
			      struct cookie_checker *checker)
{
	struct message_macs *macs = (struct message_macs *)
		((u8 *)skb->data + skb->len - sizeof(*macs));
	u8 cookie[COOKIE_LEN];
	int ret;

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE);
	dst->receiver_index = index;
	ret = wc_get_random_bytes(dst->nonce, COOKIE_NONCE_LEN);

	if (ret == 0)
		ret = make_cookie(cookie, skb, checker);

	if (ret == 0)
		ret = wc_AesGcm_oneshot_encrypt(dst->encrypted_cookie, sizeof(dst->encrypted_cookie), checker->cookie_encryption_key, sizeof(checker->cookie_encryption_key), cookie, COOKIE_LEN,
					dst->nonce, sizeof(dst->nonce),
						macs->mac1, COOKIE_LEN, NOISE_AUTHTAG_LEN);

	return ret;
}

int wg_cookie_message_consume(struct message_handshake_cookie *src,
			       struct wg_device *wg)
{
	struct wg_peer *peer = NULL;
	u8 cookie[COOKIE_LEN];
	bool ret;

	if (unlikely(!wg_index_hashtable_lookup(wg->index_hashtable,
						INDEX_HASHTABLE_HANDSHAKE |
						INDEX_HASHTABLE_KEYPAIR,
						src->receiver_index, &peer)))
		return -ENOENT;

	down_read(&peer->latest_cookie.lock);
	if (unlikely(!peer->latest_cookie.have_sent_mac1)) {
		up_read(&peer->latest_cookie.lock);
		goto out;
	}

	ret = wc_AesGcm_oneshot_decrypt(cookie, (word32)sizeof(cookie),
					peer->latest_cookie.cookie_decryption_key, sizeof(peer->latest_cookie.cookie_decryption_key),
					src->encrypted_cookie, (word32)sizeof(src->encrypted_cookie),
					src->nonce, (word32)sizeof(src->nonce),
					peer->latest_cookie.last_mac1_sent, sizeof(peer->latest_cookie.last_mac1_sent),
					NOISE_AUTHTAG_LEN);

	up_read(&peer->latest_cookie.lock);

	if (ret == 0) {
		down_write(&peer->latest_cookie.lock);
		memcpy(peer->latest_cookie.cookie, cookie, COOKIE_LEN);
		peer->latest_cookie.birthdate = ktime_get_coarse_boottime_ns();
		peer->latest_cookie.is_valid = true;
		peer->latest_cookie.have_sent_mac1 = false;
		up_write(&peer->latest_cookie.lock);
	} else {
		net_dbg_ratelimited("%s: Could not decrypt invalid cookie response: %d\n",
				    wg->dev->name, ret);
		ret = -EBADMSG;
	}

out:
	wg_peer_put(peer);

	return ret;
}
