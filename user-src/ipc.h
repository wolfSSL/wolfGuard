/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef IPC_H
#define IPC_H

#include <stdbool.h>
#include <stdint.h>

struct wgdevice;

int ipc_set_device(struct wgdevice *dev);
int ipc_get_device(struct wgdevice **dev, const char *interface);
char *ipc_list_devices(void);

#ifndef NO_IPC_LLCRYPTO
int ipc_generate_privkey(uint8_t **privkey, size_t *privkey_len, uint8_t **pubkey,
                         size_t *pubkey_len);
int ipc_derive_pubkey(const uint8_t *privkey, size_t privkey_len, uint8_t **pubkey,
                      size_t *pubkey_len);
int ipc_generate_psk(uint8_t **psk, size_t *psk_len);
#endif /* NO_IPC_LLCRYPTO */

#if defined(__linux__) || defined(__OpenBSD__)
	#define IPC_SUPPORTS_KERNEL_INTERFACE
#endif

#endif
