// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models the genl permission gate for the key-generation commands: they must
 * require init-namespace CAP_NET_ADMIN, not user-namespaced admin.
 *   cc keygen_perm.c -o t && ./t              # fixed: passes
 *   cc -DOLD keygen_perm.c -o t && ./t        # old: asserts
 */

#include <assert.h>
#include <stdio.h>

enum { GENL_ADMIN_PERM, GENL_UNS_ADMIN_PERM };

#ifdef OLD
#define KEYGEN_FLAG GENL_UNS_ADMIN_PERM
#else
#define KEYGEN_FLAG GENL_ADMIN_PERM
#endif

/* mirrors the kernel's genl pre_doit permission check */
static int permitted(int flag, int init_ns_admin, int userns_admin)
{
	if (flag == GENL_ADMIN_PERM)
		return init_ns_admin;
	return init_ns_admin || userns_admin;       /* GENL_UNS_ADMIN_PERM */
}

int main(void)
{
	/* unprivileged user in a self-owned user+net namespace */
	assert(!permitted(KEYGEN_FLAG, 0, 1));      /* keygen denied */

	/* real init-namespace admin can still generate keys */
	assert(permitted(KEYGEN_FLAG, 1, 0));

	/* device get/set stay reachable from a user namespace */
	assert(permitted(GENL_UNS_ADMIN_PERM, 0, 1));

	printf("keygen perm: key generation restricted to init-ns admin\n");
	return 0;
}
