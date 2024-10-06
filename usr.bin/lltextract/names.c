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

RBT_HEAD(ksym_names, ksym);
RBT_HEAD(ksym_addrs, ksym);

RBT_PROTOTYPE(ksym_names, ksym, name_entry, ksym_name_cmp);
RBT_PROTOTYPE(ksym_addrs, ksym, addr_entry, ksym_addr_cmp);

static struct ksym_names _ksym_names = RBT_INITIALIZER();
static struct ksym_addrs _ksym_addrs = RBT_INITIALIZER();

void
ksym_load(void)
{
	DB *db;
	DBT key, data;
	struct nlist n;
	struct ksym *k, *ok;
	char *name;

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

		name = (char *)(k + 1);
		memcpy(name, (const char *)key.data + 1, key.size - 1);
		name[key.size - 1] = '\0';

		k->addr = n.n_value;
		k->len = 0;
		k->name = name;
		k->ref = 0;

		ok = RBT_INSERT(ksym_names, &_ksym_names, k);
		if (ok != NULL) {
			warnx("symbol name %s (%08x) already exists",
			    k->name, k->addr);
		}
		ok = RBT_INSERT(ksym_addrs, &_ksym_addrs, k);
		if (0 && ok != NULL) { 
			warnx("symbol addr %08x (%s) already exists (%s)",
			    k->addr, k->name, ok->name);
		}
	}

	db->close(db);
}

struct ksym *
ksym_find(uint32_t addr)
{
	struct ksym key = { .addr = addr };

	return (RBT_FIND(ksym_addrs, &_ksym_addrs, &key));
}

struct ksym *
ksym_nfind(uint32_t addr)
{
	struct ksym key = { .addr = addr };

	return (RBT_NFIND(ksym_addrs, &_ksym_addrs, &key));
}

struct ksym *
ksym_name(const char *name)
{
	struct ksym key = { .name = name };

	return (RBT_FIND(ksym_names, &_ksym_names, &key));
}

static inline int
ksym_addr_cmp(const struct ksym *a, const struct ksym *b)
{
	if (a->addr > b->addr)
		return (-1);
	if (a->addr < b->addr)
		return (1);
	return (0);
}

RBT_GENERATE(ksym_addrs, ksym, addr_entry, ksym_addr_cmp);

static inline int
ksym_name_cmp(const struct ksym *a, const struct ksym *b)
{
	return (strcmp(a->name, b->name));
}

RBT_GENERATE(ksym_names, ksym, name_entry, ksym_name_cmp);
