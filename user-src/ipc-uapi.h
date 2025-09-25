// SPDX-License-Identifier: MIT
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "containers.h"
#include "encoding.h"
#include "ctype.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef _WIN32
#include "ipc-uapi-windows.h"
#else
#include "ipc-uapi-unix.h"
#endif

static int userspace_set_device(struct wgdevice *dev)
{
	char hex[WG_HEX_LEN(WG_KEY_LEN_MAX)], ip[INET6_ADDRSTRLEN], host[4096 + 1], service[512 + 1];
	struct wgpeer *peer;
	struct wgallowedip *allowedip;
	FILE *f;
	int ret;
	socklen_t addr_len;

	f = userspace_interface_file(dev->name);
	if (!f)
		return -errno;
	if (fprintf(f, "set=1\n") < 0) {
		ret = errno ? -errno : -EIO;
		goto out;
	}

	if (dev->flags & WGDEVICE_HAS_PRIVATE_KEY) {
		if (!wg_to_hex(hex, WG_HEX_LEN(WG_PRIVATE_KEY_LEN), dev->private_key, sizeof(dev->private_key))) {
			ret = -EINVAL;
			goto out;
		}
		if (fprintf(f, "private_key=%s\n", hex) < 0) {
			ret = errno ? -errno : -EIO;
			goto out;
		}
	}
	if (dev->flags & WGDEVICE_HAS_LISTEN_PORT) {
		if (fprintf(f, "listen_port=%u\n", dev->listen_port) < 0) {
			ret = errno ? -errno : -EIO;
			goto out;
		}
	}
	if (dev->flags & WGDEVICE_HAS_FWMARK) {
		if (fprintf(f, "fwmark=%u\n", dev->fwmark) < 0) {
			ret = errno ? -errno : -EIO;
			goto out;
		}
	}
	if (dev->flags & WGDEVICE_REPLACE_PEERS) {
		if (fprintf(f, "replace_peers=true\n") < 0) {
			ret = errno ? -errno : -EIO;
			goto out;
		}
	}

	for_each_wgpeer(dev, peer) {
		if (!wg_to_hex(hex, WG_HEX_LEN(WG_PUBLIC_KEY_LEN), peer->public_key, sizeof(peer->public_key))) {
			ret = -EINVAL;
			goto out;
		}
		if (fprintf(f, "public_key=%s\n", hex) < 0) {
			ret = errno ? -errno : -EIO;
			goto out;
		}
		if (peer->flags & WGPEER_REMOVE_ME) {
			if (fprintf(f, "remove=true\n") < 0) {
				ret = errno ? -errno : -EIO;
				goto out;
			}
			continue;
		}
		if (peer->flags & WGPEER_HAS_PRESHARED_KEY) {
			wg_to_hex(hex, WG_HEX_LEN(WG_SYMMETRIC_KEY_LEN), peer->preshared_key, sizeof(peer->preshared_key));
			if (fprintf(f, "preshared_key=%s\n", hex) < 0) {
				ret = errno ? -errno : -EIO;
				goto out;
			}
		}
		if (peer->endpoint.addr.sa_family == AF_INET || peer->endpoint.addr.sa_family == AF_INET6) {
			addr_len = 0;
			if (peer->endpoint.addr.sa_family == AF_INET)
				addr_len = sizeof(struct sockaddr_in);
			else if (peer->endpoint.addr.sa_family == AF_INET6)
				addr_len = sizeof(struct sockaddr_in6);
			if (!getnameinfo(&peer->endpoint.addr, addr_len, host, sizeof(host), service, sizeof(service), NI_DGRAM | NI_NUMERICSERV | NI_NUMERICHOST)) {
				if (peer->endpoint.addr.sa_family == AF_INET6 && strchr(host, ':')) {
					if (fprintf(f, "endpoint=[%s]:%s\n", host, service) < 0) {
						ret = errno ? -errno : -EIO;
						goto out;
					}
				}
				else {
					if (fprintf(f, "endpoint=%s:%s\n", host, service) < 0) {
						ret = errno ? -errno : -EIO;
						goto out;
					}
				}
			}
		}
		if (peer->flags & WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) {
			if (fprintf(f, "persistent_keepalive_interval=%u\n", peer->persistent_keepalive_interval) < 0) {
				ret = errno ? -errno : -EIO;
				goto out;
			}
		}
		if (peer->flags & WGPEER_REPLACE_ALLOWEDIPS) {
			if (fprintf(f, "replace_allowed_ips=true\n") < 0) {
				ret = errno ? -errno : -EIO;
				goto out;
			}
		}
		for_each_wgallowedip(peer, allowedip) {
			if (allowedip->family == AF_INET) {
				if (!inet_ntop(AF_INET, &allowedip->ip4, ip, INET6_ADDRSTRLEN))
					continue;
			} else if (allowedip->family == AF_INET6) {
				if (!inet_ntop(AF_INET6, &allowedip->ip6, ip, INET6_ADDRSTRLEN))
					continue;
			} else
				continue;
			if (fprintf(f, "allowed_ip=%s/%d\n", ip, allowedip->cidr) < 0) {
				ret = errno ? -errno : -EIO;
				goto out;
			}
		}
	}
	if (fprintf(f, "\n") < 0) {
		ret = errno ? -errno : -EIO;
		goto out;
	}
	if (fflush(f) == EOF) {
		ret = -errno;
		goto out;
	}

	if (fscanf(f, "errno=%d\n\n", &ret) != 1)
		ret = errno ? -errno : -EPROTO;

out:

	fclose(f);
	errno = -ret;
	return ret;
}

#define NUM(max) ({ \
	unsigned long long num; \
	char *end; \
	if (!char_is_digit(value[0])) \
		break; \
	num = strtoull(value, &end, 10); \
	if (*end || num > max) \
		break; \
	num; \
})

static int wc_ecc_private_to_public_exim(const byte *private, const size_t private_len,
                                  byte *public, const size_t public_len,
                                  const int curve_id)
{
        ecc_key *key = NULL;
        int key_inited = 0;
        int ret;

        if ((private_len > UINT_MAX) ||
            (public_len > UINT_MAX))
        {
            return BAD_FUNC_ARG;
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
            WC_RNG rng;
            ret = wc_InitRng(&rng);
            if (ret != 0)
                goto out;
            ret = wc_ecc_make_pub_ex(key, NULL /* pubOut */, &rng);
            wc_FreeRng(&rng);
        }

        if (ret)
            goto out;

        {
            word32 outLen = (word32)public_len;
            PRIVATE_KEY_UNLOCK();

        #ifdef HAVE_COMP_KEY
            ret = wc_ecc_export_x963_ex(key, public, &outLen, WG_PUBLIC_KEY_COMPRESSED);
        #else
            #if WG_PUBLIC_KEY_COMPRESSED
            #error WG_PUBLIC_KEY_COMPRESSED without HAVE_COMP_KEY
            #endif
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

        return ret;
}

static int userspace_get_device(struct wgdevice **out, const char *iface)
{
	struct wgdevice *dev;
	struct wgpeer *peer = NULL;
	struct wgallowedip *allowedip = NULL;
	size_t line_buffer_len = 0, line_len, value_len;
	char *key = NULL, *value;
	FILE *f;
	int ret = -EPROTO;

	*out = dev = calloc(1, sizeof(*dev));
	if (!dev)
		return -errno;

	f = userspace_interface_file(iface);
	if (!f) {
		ret = -errno;
		free(dev);
		*out = NULL;
		return ret;
	}

	fprintf(f, "get=1\n\n");
	fflush(f);

	strncpy(dev->name, iface, IFNAMSIZ - 1);
	dev->name[IFNAMSIZ - 1] = '\0';

	while (getline(&key, &line_buffer_len, f) > 0) {
		line_len = strlen(key);
		if (line_len == 1 && key[0] == '\n')
			goto err;
		value = strchr(key, '=');
		if (!value || line_len == 0 || key[line_len - 1] != '\n')
			break;
		*value++ = key[--line_len] = '\0';
		value_len = line_len - (value - key);

		if (!peer && !strcmp(key, "private_key")) {
			if (!wg_from_hex(dev->private_key, sizeof(dev->private_key), value, value_len))
				break;
			dev->flags |= WGDEVICE_HAS_PRIVATE_KEY;
                        if (wc_ecc_private_to_public_exim(dev->private_key, sizeof(dev->private_key),
                                                          dev->public_key, sizeof(dev->public_key),
                                                          WG_CURVE_ID) == 0)
			dev->flags |= WGDEVICE_HAS_PUBLIC_KEY;
		} else if (!peer && !strcmp(key, "listen_port")) {
			dev->listen_port = NUM(0xffffU);
			dev->flags |= WGDEVICE_HAS_LISTEN_PORT;
		} else if (!peer && !strcmp(key, "fwmark")) {
			dev->fwmark = NUM(0xffffffffU);
			dev->flags |= WGDEVICE_HAS_FWMARK;
		} else if (!strcmp(key, "public_key")) {
			struct wgpeer *new_peer = calloc(1, sizeof(*new_peer));

			if (!new_peer) {
				ret = -ENOMEM;
				goto err;
			}
			allowedip = NULL;
			if (peer)
				peer->next_peer = new_peer;
			else
				dev->first_peer = new_peer;
			peer = new_peer;
			if (!wg_from_hex(dev->public_key, sizeof(dev->public_key), value, value_len))
				break;
			peer->flags |= WGPEER_HAS_PUBLIC_KEY;
		} else if (peer && !strcmp(key, "preshared_key")) {
			if (!wg_from_hex(peer->preshared_key, sizeof(peer->preshared_key), value, value_len))
				break;
			if (!wg_is_zero(peer->preshared_key, sizeof(peer->preshared_key)))
				peer->flags |= WGPEER_HAS_PRESHARED_KEY;
		} else if (peer && !strcmp(key, "endpoint")) {
			char *begin, *end;
			struct addrinfo *resolved;
			struct addrinfo hints = {
				.ai_family = AF_UNSPEC,
				.ai_socktype = SOCK_DGRAM,
				.ai_protocol = IPPROTO_UDP
			};
			if (!strlen(value))
				break;
			if (value[0] == '[') {
				begin = &value[1];
				end = strchr(value, ']');
				if (!end)
					break;
				*end++ = '\0';
				if (*end++ != ':' || !*end)
					break;
			} else {
				begin = value;
				end = strrchr(value, ':');
				if (!end || !*(end + 1))
					break;
				*end++ = '\0';
			}
			if (getaddrinfo(begin, end, &hints, &resolved) != 0) {
				ret = ENETUNREACH;
				goto err;
			}
			if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) ||
			    (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6)))
				memcpy(&peer->endpoint.addr, resolved->ai_addr, resolved->ai_addrlen);
			else  {
				freeaddrinfo(resolved);
				break;
			}
			freeaddrinfo(resolved);
		} else if (peer && !strcmp(key, "persistent_keepalive_interval")) {
			peer->persistent_keepalive_interval = NUM(0xffffU);
			peer->flags |= WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL;
		} else if (peer && !strcmp(key, "allowed_ip")) {
			struct wgallowedip *new_allowedip;
			char *end, *mask = value, *ip = strsep(&mask, "/");

			if (!mask || !char_is_digit(mask[0]))
				break;
			new_allowedip = calloc(1, sizeof(*new_allowedip));
			if (!new_allowedip) {
				ret = -ENOMEM;
				goto err;
			}
			if (allowedip)
				allowedip->next_allowedip = new_allowedip;
			else
				peer->first_allowedip = new_allowedip;
			allowedip = new_allowedip;
			allowedip->family = AF_UNSPEC;
			if (strchr(ip, ':')) {
				if (inet_pton(AF_INET6, ip, &allowedip->ip6) == 1)
					allowedip->family = AF_INET6;
			} else {
				if (inet_pton(AF_INET, ip, &allowedip->ip4) == 1)
					allowedip->family = AF_INET;
			}
			allowedip->cidr = strtoul(mask, &end, 10);
			if (*end || allowedip->family == AF_UNSPEC || (allowedip->family == AF_INET6 && allowedip->cidr > 128) || (allowedip->family == AF_INET && allowedip->cidr > 32))
				break;
		} else if (peer && !strcmp(key, "last_handshake_time_sec"))
			peer->last_handshake_time.tv_sec = NUM(0x7fffffffffffffffULL);
		else if (peer && !strcmp(key, "last_handshake_time_nsec"))
			peer->last_handshake_time.tv_nsec = NUM(0x7fffffffffffffffULL);
		else if (peer && !strcmp(key, "rx_bytes"))
			peer->rx_bytes = NUM(0xffffffffffffffffULL);
		else if (peer && !strcmp(key, "tx_bytes"))
			peer->tx_bytes = NUM(0xffffffffffffffffULL);
		else if (!strcmp(key, "errno"))
			ret = -NUM(0x7fffffffU);
	}
	ret = -EPROTO;
err:
	free(key);
	if (ret) {
		free_wgdevice(dev);
		*out = NULL;
	}
	fclose(f);
	errno = -ret;
	return ret;

}
#undef NUM
