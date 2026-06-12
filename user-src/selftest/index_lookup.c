// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models wg_index_hashtable_lookup(): a failed refcount acquisition during peer
 * teardown must not clobber the entry's stored owner pointer, which other code
 * (keypair cleanup, send paths) dereferences.
 *   cc index_lookup.c -o t && ./t              # fixed: passes
 *   cc -DOLD index_lookup.c -o t && ./t        # old: asserts
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>

struct peer { int refcount; };
struct entry { struct peer *peer; };

/* mirrors wg_peer_get_maybe_zero(): NULL once the refcount has hit zero */
static struct peer *get_maybe_zero(struct peer *p)
{
	if (!p || p->refcount == 0)
		return NULL;
	++p->refcount;
	return p;
}

static struct entry *lookup(struct entry *e, struct peer **out)
{
	if (e) {
#ifdef OLD
		e->peer = get_maybe_zero(e->peer);
		if (e->peer)
			*out = e->peer;
		else
			e = NULL;
#else
		struct peer *entry_peer = get_maybe_zero(e->peer);

		if (entry_peer)
			*out = entry_peer;
		else
			e = NULL;
#endif
	}
	return e;
}

int main(void)
{
	struct peer p;
	struct entry e;
	struct peer *out = NULL;

	/* teardown: refcount already zero, lookup must fail but keep e.peer stable */
	p.refcount = 0;
	e.peer = &p;
	assert(lookup(&e, &out) == NULL);
	assert(e.peer == &p);          /* owner pointer not clobbered */

	/* live peer: lookup succeeds, takes a ref, owner pointer unchanged */
	p.refcount = 1;
	e.peer = &p;
	out = NULL;
	assert(lookup(&e, &out) == &e);
	assert(out == &p);
	assert(e.peer == &p);
	assert(p.refcount == 2);

	printf("index lookup: owner pointer stable across failed acquisition\n");
	return 0;
}
