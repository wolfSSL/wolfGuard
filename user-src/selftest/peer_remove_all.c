// SPDX-License-Identifier: GPL-2.0
/*
 * Portions Copyright (C) 2020-2026 wolfSSL Inc. <info@wolfssl.com>
 *
 * Models wg_peer_remove_all(): a removed dump cursor's peer_list must stay
 * self-referential (empty) so wg_get_device_dump's guard fires instead of
 * walking a dangling pointer into freed peer memory.
 *   cc peer_remove_all.c -o t && ./t              # fixed: passes
 *   cc -DOLD peer_remove_all.c -o t && ./t        # old: asserts
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>

struct list_head { struct list_head *next, *prev; };

#define INIT_LIST_HEAD(p) do { (p)->next = (p); (p)->prev = (p); } while (0)
#define LIST_HEAD(n) struct list_head n = { &(n), &(n) }

static int list_empty(const struct list_head *h) { return h->next == h; }

static void __list_add(struct list_head *n, struct list_head *p, struct list_head *x)
{
	x->prev = n; n->next = x; n->prev = p; p->next = n;
}
static void list_add_tail(struct list_head *n, struct list_head *h)
{
	__list_add(n, h->prev, h);
}
static void list_del_init(struct list_head *e)
{
	e->prev->next = e->next; e->next->prev = e->prev; INIT_LIST_HEAD(e);
}

struct peer {
	struct list_head peer_list;
	struct list_head dead_peer_list;
	int id;
};

#define peer_of(ptr) ((struct peer *)((char *)(ptr) - offsetof(struct peer, peer_list)))

/* mirrors peer_make_dead(): unlinks peer_list, leaving it self-referential */
static void peer_make_dead(struct peer *p) { list_del_init(&p->peer_list); }

static void remove_all(struct list_head *head)
{
	LIST_HEAD(dead);
	struct list_head *pos, *tmp;

	for (pos = head->next; pos != head; pos = tmp) {
		struct peer *p = peer_of(pos);

		tmp = pos->next;
		peer_make_dead(p);
#ifdef OLD
		list_add_tail(&p->peer_list, &dead);       /* clobbers peer_list */
#else
		list_add_tail(&p->dead_peer_list, &dead);  /* separate linkage */
#endif
	}
}

int main(void)
{
	LIST_HEAD(peer_list);
	struct peer a = { .id = 1 }, b = { .id = 2 };
	struct peer *cursor = &a;

	INIT_LIST_HEAD(&a.peer_list);
	INIT_LIST_HEAD(&b.peer_list);
	list_add_tail(&a.peer_list, &peer_list);
	list_add_tail(&b.peer_list, &peer_list);

	remove_all(&peer_list);

	/* the dump guard treats an empty cursor peer_list as "removed" */
	assert(list_empty(&cursor->peer_list));

	printf("peer_remove_all: removed cursor peer_list stays empty\n");
	return 0;
}
