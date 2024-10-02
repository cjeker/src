/*	$OpenBSD$ */

/*
 * Copyright (c) 2022 David Gwynne <dlg@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/tree.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <limits.h>
#include <db.h>
#include <nlist.h>
#include <err.h>

#include "lltextract.h"

#define DBNAME "/var/db/kvm_bsd.db"

HASHINFO openinfo = {
	4096,		/* bsize */
	128,		/* ffactor */
	1024,		/* nelem */
	2048 * 1024,	/* cachesize */
	NULL,		/* hash() */
	0		/* lorder */
};

RBT_HEAD(ksyms, ksym);

RBT_PROTOTYPE(ksyms, ksym, entry, ksym_cmp);

static struct ksyms _ksyms = RBT_INITIALIZER(ksyms);

static void
knames_load(struct ksyms *ksyms)
{
	DB *db;
	DBT key, data;
	struct nlist n;
	struct ksym *k;

	db = dbopen(DBNAME, O_RDONLY, 0, DB_HASH, NULL);
	if (db == NULL)
		err(1, "%s", DBNAME);

	for (;;) {
		int rv = db->seq(db, &key, &data, R_NEXT);
		if (rv == -1)
			errx(1, "%s seq", DBNAME);

		if (rv != 0)
			break;

		if (key.size < 2 || *(const char *)key.data != '_')
			continue;
		if (data.size != sizeof(n))
			continue;

		memcpy(&n, data.data, sizeof(n));
		//if (n.n_type != N_TEXT)
		//	continue;

		k = malloc(sizeof(*k) + key.size);
		if (k == NULL)
			err(1, "%s ksym", __func__);

		k->addr = n.n_value;
		k->len = 0;
		k->name = (char *)(k + 1);
		k->ref = 0;

		memcpy(k->name, (const char *)key.data + 1, key.size - 1);
		k->name[key.size - 1] = '\0';

		if (RBT_INSERT(ksyms, ksyms, k) != NULL)
			free(k);
	}

	db->close(db);
}

struct ksym *
ksym_find(uint32_t addr)
{
	struct ksyms *ksyms = &_ksyms;
	struct ksym key = { .addr = addr };

	if (RBT_EMPTY(ksyms, ksyms))
		knames_load(ksyms);

	return (RBT_FIND(ksyms, ksyms, &key));
}

struct ksym *
ksym_nfind(uint32_t addr)
{
	struct ksyms *ksyms = &_ksyms;
	struct ksym key = { .addr = addr };

	if (RBT_EMPTY(ksyms, ksyms))
		knames_load(ksyms);

	return (RBT_NFIND(ksyms, ksyms, &key));
}

static inline int
ksym_cmp(const struct ksym *a, const struct ksym *b)
{
	if (a->addr > b->addr)
		return (-1);
	if (a->addr < b->addr)
		return (1);
	return (0);
}

RBT_GENERATE(ksyms, ksym, entry, ksym_cmp);
