/*	$OpenBSD */

/*
 * Copyright (c) 2022 The University of Queensland
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

/*
 *
 * Copyright 2021 Richard L. Sites
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/syscall.h> /* for SYS_MAXSYSCALL */
#include <sys/syslimits.h> /* for _MAXCOMLEN */
#include <sys/tree.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <err.h>

#include <sys/lltrace.h>
#include "heap.h"

#include "fxt.h"
#include "lltextract.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef ISSET
#define ISSET(_a, _b) ((_a) & (_b))
#endif

#define	THREAD_PID_OFFSET	100000

struct cytime {
	uint64_t	base_cy;
	uint64_t	base_ns;
	uint64_t	base_cy10;
	uint64_t	base_ns10;

	double		slope;
};

struct ring {
	uint64_t	slots[8192];
};

static void		lltextract(size_t, const struct ring *);

struct llt_pid {
	/* this knows a lot about process names in the kernel */
	union {
		uint64_t		words[3];
		char			str[_MAXCOMLEN];
	}			_ps_comm;
#define ps_comm			_ps_comm.str
#define ps_comm64		_ps_comm.words
	unsigned int		 ps_comm_n;
	unsigned int		 ps_strid;

	unsigned int		 ps_pid;
	unsigned int		 ps_system;
	uint64_t		 ps_fxtid;

	uint64_t		 ps_ts;
	RBT_ENTRY(llt_pid)	 ps_entry;
};

RBT_HEAD(llt_pid_tree, llt_pid);

static inline int
llt_pid_cmp(const struct llt_pid *a, const struct llt_pid *b)
{
	if (a->ps_pid > b->ps_pid)
		return (1);
	if (a->ps_pid < b->ps_pid)
		return (-1);
	return (0);
}

struct llt_tid {
	struct llt_pid		*p_p;
	unsigned int		 p_strid;
	//unsigned int		 p_thrid;
	unsigned int		 p_tid;
	uint64_t		 p_fxtid;

	RBT_ENTRY(llt_tid)	 p_entry;
};

RBT_HEAD(llt_tid_tree, llt_tid);

static inline int
llt_tid_cmp(const struct llt_tid *a, const struct llt_tid *b)
{
	if (a->p_tid > b->p_tid)
		return (1);
	if (a->p_tid < b->p_tid)
		return (-1);
	return (0);
}

RBT_PROTOTYPE(llt_pid_tree, llt_pid, ps_entry, llt_pid_cmp);
RBT_PROTOTYPE(llt_tid_tree, llt_tid, p_entry, llt_tid_cmp);

struct lltx_fxt_record {
	HEAP_ENTRY(lltx_fxt_record)
				entry;
	uint64_t		ts;
	unsigned int		n;

	/* followed by n * uint64_ts */
};

HEAP_HEAD(lltx_fxt_heap);

HEAP_PROTOTYPE(lltx_fxt_heap, lltx_fxt_record);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-v] -i infile -o outfile\n",
	    __progname);

	exit(1);
}

static const uint64_t fxt_magic[] = { htole64(FXT_INIT_MAGIC) };
static const uint64_t fxt_init[2] = { FXT_INIT_RECORD(1000000000ULL) };

static FILE *ifile = stdin;
static FILE *ofile = stdout;
static int verbose = 0;

static struct llt_pid_tree lltx_pids = RBT_INITIALIZER();
static struct llt_tid_tree lltx_tids = RBT_INITIALIZER();

static void		lltx_kobj_bsd(void);
static unsigned int	lltx_str(const char *);

static unsigned int lltx_strids;
static unsigned int lltx_strid_process;
static unsigned int lltx_strid_sched;
static unsigned int lltx_strid_wakeup;
static unsigned int lltx_strid_woken;
static unsigned int lltx_strid_unknown;
static unsigned int lltx_strid_acquire;
static unsigned int lltx_strid_symbol;
static unsigned int lltx_strid_offset;
static unsigned int lltx_strid_count;

static const char str_process[] = "process";
static const char str_sched[] = "sched";
static const char str_wakeup[] = "wakeup";
static const char str_woken[] = "woken";
static const char str_unknown[] = "unknown";
static const char str_acquire[] = "acquire";
static const char str_symbol[] = "symbol";
static const char str_offset[] = "offset";
static const char str_count[] = "count";

static const char *str_locks[1 << LLTRACE_LK_TYPE_WIDTH] = {
	[LLTRACE_LK_RW] = "rwlock",
	[LLTRACE_LK_MTX] = "mutex",
	[LLTRACE_LK_K] = "kernel",
};
static unsigned int lltx_strids_locks[1 << LLTRACE_LK_TYPE_WIDTH];

static const char *str_lock_ops[1 << LLTRACE_LK_PHASE_WIDTH] = {
	[LLTRACE_LK_I_EXCL] = "instant-exclusive",
	[LLTRACE_LK_I_SHARED] = "instant-shared",
	[LLTRACE_LK_A_START] = "acquire-start",
	[LLTRACE_LK_A_EXCL] = "acquired-exclusive",
	[LLTRACE_LK_A_SHARED] = "acquired-shared",
	[LLTRACE_LK_A_ABORT] = "acquire-abort",
	[LLTRACE_LK_DOWNGRADE] = "downgrade",
	[LLTRACE_LK_R_EXCL] = "release-exclusive",
	[LLTRACE_LK_R_SHARED] = "release-shared",
	[LLTRACE_LK_I_FAIL] = "instant-fail",
};
static unsigned int lltx_strids_lock_ops[1 << LLTRACE_LK_PHASE_WIDTH];

static struct lltx_fxt_heap lltx_records = HEAP_INITIALIZER();

static void
fxt_insert(uint64_t ts, const uint64_t *atoms, unsigned int n)
{
	struct lltx_fxt_record *r;
	uint64_t *dst;
	unsigned int i;

	r = malloc(sizeof(*r) + (sizeof(*atoms) * n));
	if (r == NULL)
		err(1, "fxt_insert");

	r->ts = ts;
	r->n = n;
	dst = (uint64_t *)(r + 1);
	for (i = 0; i < n; i++)
		dst[i] = atoms[i];

	HEAP_INSERT(lltx_fxt_heap, &lltx_records, r);
}

static struct lltx_fxt_record *
fxt_extract(void)
{
	return (HEAP_EXTRACT(lltx_fxt_heap, &lltx_records));
}

static inline size_t
fxt_write(const uint64_t *w, size_t n, FILE *f)
{
	return fwrite(w, sizeof(*w), n, f);
}

int
main(int argc, char *argv[])
{
	const char *ifname = NULL;
	const char *ofname = NULL;
	const char *ofmode = "wx";
	struct ring ring;
	size_t block = 0;
	size_t rv;
	size_t i;

	int ch;

	while ((ch = getopt(argc, argv, "fi:o:v")) != -1) {
		switch (ch) {
		case 'f':
			ofmode = "w";
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'o':
			ofname = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (ifname == NULL)
		warnx("input file not specified");
	if (ofname == NULL)
		warnx("output file not specified");
	if (ifname == NULL || ofname == NULL)
		usage();

	ifile = fopen(ifname, "r");
	if (ifile == NULL)
		err(1, "%s", ifname);

	ofile = fopen(ofname, ofmode);
	if (ofile == NULL)
		err(1, "%s", ofname);

	rv = fxt_write(fxt_magic, nitems(fxt_magic), ofile);
	if (rv == 0)
		err(1, "%s fxt magic write", ofname);

	rv = fxt_write(fxt_init, nitems(fxt_init), ofile);
	if (rv == 0)
		err(1, "%s fxt ts write", ofname);

	lltx_kobj_bsd();
	lltx_strid_process = lltx_str(str_process);
	lltx_strid_sched = lltx_str(str_sched);
	lltx_strid_wakeup = lltx_str(str_wakeup);
	lltx_strid_woken = lltx_str(str_woken);
	lltx_strid_unknown = lltx_str(str_unknown);
	lltx_strid_acquire = lltx_str(str_acquire);
	lltx_strid_symbol = lltx_str(str_symbol);
	lltx_strid_offset = lltx_str(str_offset);
	lltx_strid_count = lltx_str(str_count);

	for (i = 0; i < nitems(str_locks); i++) {
		const char *str = str_locks[i];
		if (str == NULL)
			continue;
		lltx_strids_locks[i] = lltx_str(str);
	}

	for (i = 0; i < nitems(str_lock_ops); i++) {
		const char *str = str_lock_ops[i];
		if (str == NULL)
			continue;
		lltx_strids_lock_ops[i] = lltx_str(str);
	}

printf("[\n");
	for (;;) {
		size_t nread = fread(&ring, sizeof(ring), 1, ifile);
		if (nread == 0) {
			if (ferror(ifile))
				errx(1, "error reading %s", ifname);
			if (feof(ifile))
				break;
		}

		lltextract(block++, &ring);
	}

	{
		struct llt_tid *p;

		RBT_FOREACH(p, llt_tid_tree, &lltx_tids) {
			printf("### pid %u tid %u -> %llu %llu\n",
			    p->p_p->ps_pid, p->p_tid,
			    p->p_p->ps_fxtid, p->p_fxtid);
		}
	}

	{
		struct lltx_fxt_record *r;

		while ((r = fxt_extract()) != NULL) {
			uint64_t *atoms = (uint64_t *)(r + 1);
			fxt_write(atoms, r->n, ofile);
			free(r);
		}
	}

	return (0);
}


static int
printable(int ch)
{
        if (ch == '\0')
                return ('_');
        if (!isprint(ch))
                return ('~');

        return (ch);
}

static void
dump_slot(size_t slot, uint64_t v)
{
	uint8_t buf[sizeof(v)];
	size_t i;

	printf("## slot %4zu = 0x%016llx |", slot, v);

	memcpy(buf, &v, sizeof(buf));
	for (i = 0; i < sizeof(buf); i++)
		putchar(printable(buf[i]));

	printf("|\n");
}

static void
dump_slots(const struct ring *ring, size_t slot, size_t n)
{
	n += slot;
	while (slot < n) {
		dump_slot(slot, ring->slots[slot]);
		slot++;
	}
}

static void
cytime_init(struct cytime *ct,
    uint64_t start_cy, uint64_t start_ns, uint64_t stop_cy, uint64_t stop_ns)
{
	uint64_t diff_cy = stop_cy - start_cy;
	uint64_t diff_ns = stop_ns - start_ns;

	ct->base_cy = start_cy;
	ct->base_ns = start_ns;

	ct->slope = (double)diff_ns / (double)diff_cy;

	if (verbose >= 1) {
		printf("SetParams maps %18llucy ==> %18lluns\n",
		    start_cy, start_ns);
		printf("SetParams maps %18llucy ==> %18lluns\n",
		    stop_cy, stop_ns);
		printf("          diff %18llucy ==> %18lluns\n",
		    diff_cy, diff_ns);
		printf("SetParams slope %f ns/cy\n", ct->slope);
	}
}

struct lltstate {
	struct cytime	 ct;

	uint32_t	 cy32;
	int64_t		 cy;
	unsigned int	 cpu;
	unsigned int	 idletid;

	uint64_t	 ns;
	struct llt_tid	*p;

	unsigned int	 idle;
};

#define TS32_SHIFT (32 - (LLTRACE_TS_WIDTH + LLTRACE_TS_SHIFT))

struct llevent {
	size_t		 block;
	size_t		 slot;
	int64_t		 cy;
	uint32_t	 cy32;
};

#if 0
static void	lltextract_mark(struct lltstate *, struct llevent *,
		    unsigned int, uint64_t);
static void	lltextract_irq(struct lltstate *, struct llevent *,
		    unsigned int, uint64_t);
static void	lltextract_syscall(struct lltstate *, struct llevent *,
		    unsigned int, uint64_t);
static void	lltextract_sysret(struct lltstate *, struct llevent *,
		    unsigned int, uint64_t);
#endif

static void	lltx_id(struct lltstate *, struct llevent *, uint64_t,
		    const uint64_t *, unsigned int);
static void	lltx_event(struct lltstate *, struct llevent *, uint64_t,
		    const uint64_t *, unsigned int);
static void	lltx_locking(struct lltstate *, struct llevent *, uint64_t,
		    const uint64_t *, unsigned int);
static void	lltx_idle(struct lltstate *, struct llevent *, unsigned int);

static struct llt_tid *
lltx_tid(unsigned int tid)
{
	struct llt_tid *p;
	struct llt_tid key = { .p_tid = tid };

	p = RBT_FIND(llt_tid_tree, &lltx_tids, &key);
	if (p != NULL)
		return (p);

	p = malloc(sizeof(*p));
	if (p == NULL)
		err(1, "llt tid alloc");

	p->p_tid = tid;

	p->p_p = NULL;
	p->p_strid = 0;
	//p->p_thrid = 0;
	p->p_fxtid = p->p_tid + THREAD_PID_OFFSET;

	if (RBT_INSERT(llt_tid_tree, &lltx_tids, p) != NULL)
		errx(1, "llt tid %d insert failed", tid);

	return (p);
}

static struct llt_tid *
lltx_tid_pid(unsigned int tid, unsigned int pid, unsigned int sys)
{
	struct llt_tid *p;
	struct llt_pid *ps;

	p = lltx_tid(tid);
	ps = p->p_p;
	if (ps == NULL) {
		struct llt_pid key = { .ps_pid = pid };

		ps = RBT_FIND(llt_pid_tree, &lltx_pids, &key);
		if (ps == NULL) {
			ps = malloc(sizeof(*ps));
			if (ps == NULL)
				err(1, "llt pid alloc");

			ps->ps_pid = pid;
			ps->ps_system = sys;

			ps->ps_strid = 0;
			ps->ps_ts = 0;

			/* lie about kernel threads */
			ps->ps_fxtid = ps->ps_system ? 0 : ps->ps_pid;

			if (RBT_INSERT(llt_pid_tree, &lltx_pids, ps) != NULL)
				errx(1, "llt pid %u insert failed", pid);
		}

		p->p_p = ps;
		p->p_fxtid = ps->ps_system ? ps->ps_pid :
		    (p->p_tid + THREAD_PID_OFFSET);

		if (!ps->ps_system) {
			uint64_t atoms[4];

			atoms[0] = htole64(FXT_T_KOBJ);
			atoms[0] |= htole64(nitems(atoms) << FXT_H_SIZE_SHIFT);
			atoms[0] |= htole64(2ULL << 16); /* ZX_OBJ_TYPE_THREAD */
			atoms[0] |= htole64(1ULL << 40); /* number of args */
			atoms[1] = htole64(p->p_fxtid);
			atoms[2] = htole64(8 | (2 << 4)); /* koid */
			atoms[2] |= htole64((uint64_t)lltx_strid_process << 16);
			atoms[3] = htole64(ps->ps_fxtid);

			fxt_write(atoms, nitems(atoms), ofile);
		}
	} else {
		if (ps->ps_pid != pid)
			errx(1, "tid %u has a new pid %u", tid, pid);
	}

	return (p);
}

static void
lltextract(size_t block, const struct ring *ring)
{
	const struct lltrace_header *llh = (struct lltrace_header *)ring;
	struct lltstate state = {
		.cpu = llh->h_cpu,
		.idletid = llh->h_idletid,
		.cy = 0,
		.idle = LLTRACE_EVENT_PHASE_END,
	};
	struct llevent lle;
	unsigned int pid, sys;

	size_t slot, nslot;
	uint32_t cy32;
	int32_t cydiff;

	if (verbose >= 2)
		dump_slots(ring, 0, 8);

	cytime_init(&state.ct, ring->slots[2], ring->slots[3],
	    ring->slots[4], ring->slots[5]);

	printf("{");
	printf("\"name\":\"cpu%u\",", state.cpu);
	printf("\"cat\":\"lltrace\",");
	printf("\"ph\":\"b\",");
	printf("\"pid\":0,");
	printf("\"tid\":%u,", state.cpu);
	printf("\"ts\":%lf,", (double)ring->slots[3] / 1000.0);
	printf("\"id\":%zu", block);
	printf("},\n");

	printf("{");
	printf("\"name\":\"cpu%u\",", state.cpu);
	printf("\"cat\":\"lltrace\",");
	printf("\"ph\":\"e\",");
	printf("\"pid\":0,");
	printf("\"tid\":%u,", state.cpu);
	printf("\"ts\":%lf,", (double)ring->slots[5] / 1000.0);
	printf("\"id\":%zu", block);
	printf("},\n");

	state.cy32 = ring->slots[2] << TS32_SHIFT;
	state.ns = state.ct.base_ns;

	sys = llh->h_pid & (1U << 31);
	pid = llh->h_pid & ~(1U << 31);

	state.p = lltx_tid_pid(llh->h_tid, pid, sys);

	for (slot = 8; slot < nitems(ring->slots); slot++) {
		const uint64_t *slots = ring->slots + slot;
		uint64_t record = slots[0];
		unsigned int type, len;

		if (verbose >= 2)
			dump_slot(slot, record);

		if (record == 0)
			return;

		type = (record >> LLTRACE_TYPE_SHIFT) & LLTRACE_TYPE_MASK;
		len = (record >> LLTRACE_LEN_SHIFT) & LLTRACE_LEN_MASK;

		nslot = slot + len;
		if (nslot >= nitems(ring->slots))
			errx(1, "slot %zu has %u extra", slot, len);

		if (verbose >= 2) {
			dump_slots(ring, slot + 1, len);
			printf("slot %4zu+%u type 0x%x\n", slot, len, type);
		}

		if (ISSET(LLTRACE_TS_TYPES, 1U << type)) {
			cy32 = record & (LLTRACE_TS_MASK << LLTRACE_TS_SHIFT);
			cy32 <<= TS32_SHIFT;
			cydiff = (cy32 - state.cy32);
			cydiff >>= TS32_SHIFT;

			int64_t cy = state.cy + cydiff;
			if (cydiff > 0) {
				state.cy32 = cy32;
				state.cy += cydiff;
			}
			//lle.cy = state.cy;
			state.ns = state.ct.base_ns + (cy * state.ct.slope);
			//state.ns = state.ct.base_cy + cy;

			if (verbose >= 2) {
				printf("state.cy %llu state.cy32 %u diff %d (%.1f)\n",
				     state.cy, state.cy32, cydiff, cydiff * state.ct.slope);
			}

			if (state.idle == LLTRACE_EVENT_PHASE_START) {
				lltx_idle(&state, &lle,
				    LLTRACE_EVENT_PHASE_END);
			}
		}

		lle.block = block;
		lle.slot = slot;

		switch (type) {
		case LLTRACE_TYPE_ID:
			lltx_id(&state, &lle, record, slots + 1, len);
			break;
		case LLTRACE_TYPE_EVENT:
			lltx_event(&state, &lle, record, slots + 1, len);
			break;
		case LLTRACE_TYPE_LOCKING:
			lltx_locking(&state, &lle, record, slots + 1, len);
			break;
		default:
			warnx("slot %4zu+%u unknown type 0x%x ",
			    slot, len, type);
			break;
		}

		slot = nslot;
	}
}

static size_t
strtoatoms(uint64_t *atoms, size_t n, const char *str, size_t len)
{
	size_t natoms = (len + (sizeof(*atoms) - 1)) / sizeof(*atoms);
	size_t nn = n + natoms;
	size_t i;

	if (nn >= FXT_MAX_WORDS)
		errx(1, "too far");

	for (i = n; i < nn; i++)
		atoms[i] = 0;

	memcpy(atoms + n, str, len);

	return (nn);
}

static int
str64eq(const uint64_t *a, const uint64_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (a[i] != b[i])
			return (0);
	}

	return (1);
}

uint64_t fxt_atoms[128];

static void
lltx_id_tid(struct lltstate *state, struct llevent *lle, uint64_t record,
    const uint64_t *extra, unsigned int extralen)
{
	unsigned int tid, pid, sys;
	struct llt_tid *p;
	struct llt_pid *ps;
	unsigned int i;
	size_t n;

	tid = (record >> LLTRACE_ID_TID_SHIFT) & LLTRACE_ID_TID_MASK;
	pid = (record >> LLTRACE_ID_TID_PID_SHIFT) & LLTRACE_ID_TID_PID_MASK;
	sys = !!ISSET(record, LLTRACE_ID_TID_SYSTEM);

	printf("#pn %zu[%zu] cpu %u %s pid %u tid %u",
	    lle->block, lle->slot, state->cpu,
	    sys ? "kernel" : "user", pid, tid);
	if (extralen > 0) {
		printf(" %.*s",
		    (int)(extralen * sizeof(*extra)), (const char *)extra);
	}
	printf("\n");

	p = lltx_tid_pid(tid, pid, sys);
	ps = p->p_p;

//	state->tid = tid;
//	state->p = p;

	if (ps->ps_ts > state->ns) {
		/* a later version of the info has already been reported */
		return;
	}
	ps->ps_ts = state->ns;

	if (extralen > nitems(ps->ps_comm64))
		errx(1, "pid %d name is too long", ps->ps_pid);

	if (ps->ps_comm_n == extralen &&
	    str64eq(ps->ps_comm64, extra, extralen))
		return;

	for (i = 0; i < extralen; i++)
		ps->ps_comm64[i] = extra[i];
	while (i < nitems(ps->ps_comm64))
		ps->ps_comm64[i++] = 0;
	ps->ps_comm_n = extralen;

	fxt_atoms[0] = htole64(FXT_T_KOBJ);

	n = 1;
	if (ps->ps_system) {
		fxt_atoms[0] |= htole64(2 << 16); /* ZX_OBJ_TYPE_THREAD */
		fxt_atoms[n++] = htole64(p->p_fxtid);
	} else {
		fxt_atoms[0] |= htole64(1 << 16); /* ZX_OBJ_TYPE_PROCESS */
		fxt_atoms[n++] = htole64(ps->ps_fxtid);
	}
	for (i = 0; i < extralen; i++)
		fxt_atoms[n++] = extra[i];
	fxt_atoms[0] |= htole64(n << 4);
	fxt_atoms[0] |= htole64(((1 << 15) |
	    strnlen(ps->ps_comm, ps->ps_comm_n * 8)) << 24);

	fxt_write(fxt_atoms, n, ofile);
}

static void
lltx_kobj_bsd(void)
{
	static const char name[] = "/bsd";
	size_t namelen = sizeof(name) - 1; /* - nul */
	size_t n;

	n = 1;
	fxt_atoms[n++] = 0; /* pid 0 is the kernel */
	n = strtoatoms(fxt_atoms, n, name, namelen);

	fxt_atoms[0] = htole64(FXT_T_KOBJ);
	fxt_atoms[0] |= htole64(1 << 16); /* ZX_OBJ_TYPE_PROCESS */
	fxt_atoms[0] |= htole64(n << 4);
	fxt_atoms[0] |= htole64(((1 << 15) | namelen) << 24);

	fxt_write(fxt_atoms, n, ofile);
}

static unsigned int
lltx_str(const char *str)
{
	size_t len = strlen(str);
	uint64_t strid = ++lltx_strids;
	size_t n;

	n = strtoatoms(fxt_atoms, 1, str, len);

	fxt_atoms[0] = htole64(FXT_T_STRING | (n << 4));
	fxt_atoms[0] |= htole64(strid << 16);
	fxt_atoms[0] |= htole64((uint64_t)len << 32);

	fxt_write(fxt_atoms, n, ofile);

	return (strid);
}

static void
lltx_id(struct lltstate *state, struct llevent *lle, uint64_t record,
    const uint64_t *extra, unsigned int n)
{
	unsigned int type;

	type = (record >> LLTRACE_ID_TYPE_SHIFT) & LLTRACE_ID_TYPE_MASK;

	switch (type) {
	case LLTRACE_ID_TYPE_TID:
		lltx_id_tid(state, lle, record, extra, n);
		break;
	default:
		warnx("slot %4zu+%u unknown id type 0x%x ", lle->slot, n,
		    type);
		break;
	}
}

static const char *lltrace_event_class_names[] = {
	[LLTRACE_EVENT_CLASS_SYSCALL]	= "syscall",
	[LLTRACE_EVENT_CLASS_IDLE]	= "idle",
	[LLTRACE_EVENT_CLASS_INTR]	= "intr",
	[LLTRACE_EVENT_CLASS_SCHED]	= "sched",
	[LLTRACE_EVENT_CLASS_FUNC]	= "function",
	[LLTRACE_EVENT_CLASS_PAGEFAULT]	= "pagefault",
	[LLTRACE_EVENT_CLASS_WAKE]	= "wake",
	[LLTRACE_EVENT_CLASS_COUNT]	= "count",
};

static const char *lltrace_event_phase_names[] = {
	[LLTRACE_EVENT_PHASE_INSTANT] = "instant",
	[LLTRACE_EVENT_PHASE_START] = "start",
	[LLTRACE_EVENT_PHASE_STEP] = "step",
	[LLTRACE_EVENT_PHASE_END] = "end",
};

static const unsigned int lltrace_event_phase_map[] = {
	[LLTRACE_EVENT_PHASE_INSTANT] = 0,
	[LLTRACE_EVENT_PHASE_START] = 2,
	[LLTRACE_EVENT_PHASE_END] = 3,
};

static const char *lltrace_intr_type_names[1 << LLTRACE_INTR_T_WIDTH] = {
	[LLTRACE_INTR_T_HW] = "hardintr",
	[LLTRACE_INTR_T_SW] = "softintr",
	[LLTRACE_INTR_T_IPI] = "ipi",
	[LLTRACE_INTR_T_CLOCK] = "clockintr",
};

static const char *lltrace_count_type_names[] = {
	[LLTRACE_COUNT_T_PKTS_IFIQ] = "pkts:ifiq",
	[LLTRACE_COUNT_T_PKTS_NETTQ] = "pkts:nettq",
	[LLTRACE_COUNT_T_PKTS_IFQ] = "pkts:ifq",
	[LLTRACE_COUNT_T_PKTS_QDROP] = "pkts:qdrop",
	[LLTRACE_COUNT_T_PKTS_HDROP] = "pkts:hdrop",
};

static const char *
syscall_name(unsigned int sc)
{
	extern const char *const syscallnames[];

	if (sc < SYS_MAXSYSCALL)
		return (syscallnames[sc]);

	return (NULL);
}

#if 0
static uint64_t
lltx_thrid(struct llt_tid *p)
{
	static unsigned int thrids;
	unsigned int thrid = p->p_thrid;
	uint64_t atoms[3];

	if (thrid != 0)
		return thrid;

	thrid = ++thrids;
	p->p_thrid = thrid;

	/* XXX not the nicest place to do this */
	atoms[0] = htole64(FXT_T_THREAD | (nitems(atoms) << FXT_H_SIZE_SHIFT));
	atoms[0] |= htole64(thrid << 16);
	atoms[1] = htole64(p->p_p->ps_fxtid);
	atoms[2] = htole64(p->p_fxtid);

	printf("#th 0x%016llx %llu %llu\n", atoms[0], atoms[1], atoms[2]);

	fxt_write(atoms, nitems(atoms), ofile);

	return (thrid);
}
#endif

static void
lltx_sched(struct lltstate *state, struct llevent *lle, uint64_t record,
    const uint64_t *extra, unsigned int extralen)
{
	unsigned int ntid, ostate;
	struct llt_tid *op = state->p;
	struct llt_tid *np;
//	uint64_t oid, nid;
	size_t n;

	ntid = (record >> LLTRACE_SCHED_TID_SHIFT) &
	    LLTRACE_SCHED_TID_MASK;
	ostate = (record >> LLTRACE_SCHED_STATE_SHIFT) &
	    LLTRACE_SCHED_STATE_MASK;

	np = lltx_tid(ntid);
	if (np->p_p == NULL)
		errx(1, "new thread %u is unknown", ntid);

	if (verbose >= 2) {
		printf("#ev %zu[%zu] %llu cpu %u pid %llu tid %llu "
		    "switch to pid %llu tid %llu\n",
		    lle->block, lle->slot, state->ns, state->cpu,
		    op->p_p->ps_fxtid, op->p_fxtid,
		    np->p_p->ps_fxtid, np->p_fxtid);
	}

	if (extralen > 0) {
		n = 1;
		fxt_atoms[n++] = htole64(state->ns);
		fxt_atoms[n++] = htole64(np->p_p->ps_fxtid);
		fxt_atoms[n++] = htole64(np->p_fxtid);

		fxt_atoms[0] = htole64(FXT_T_EVENT | (n << FXT_H_SIZE_SHIFT));
		fxt_atoms[0] |= htole64((uint64_t)0 << 16); /* instant event */
		fxt_atoms[0] |= htole64(0ULL << 20); /* number of args */
		//fxt_atoms[0] |= htole64(nid << 24);
		fxt_atoms[0] |= htole64((uint64_t)lltx_strid_sched << 32);
		fxt_atoms[0] |= htole64((uint64_t)lltx_strid_woken << 48);

		//fxt_write(fxt_atoms, n, ofile);
		fxt_insert(state->ns, fxt_atoms, n);

		n = 1;
		fxt_atoms[n++] = htole64(state->ns);
		fxt_atoms[n++] = htole64(np->p_p->ps_fxtid);
		fxt_atoms[n++] = htole64(np->p_fxtid);
		fxt_atoms[n++] = htole64(extra[0]);

		fxt_atoms[0] = htole64(FXT_T_EVENT | (n << FXT_H_SIZE_SHIFT));
		fxt_atoms[0] |= htole64((uint64_t)10 << 16);
		fxt_atoms[0] |= htole64(0ULL << 20); /* number of args */
		//fxt_atoms[0] |= htole64(nid << 24);
		fxt_atoms[0] |= htole64((uint64_t)lltx_strid_sched << 32);
		fxt_atoms[0] |= htole64((uint64_t)lltx_strid_wakeup << 48);

		//fxt_write(fxt_atoms, n, ofile);
		fxt_insert(state->ns, fxt_atoms, n);
	}

//	oid = lltx_thrid(op);
//	nid = lltx_thrid(np);

	n = 1;
	fxt_atoms[n++] = htole64(state->ns);
	fxt_atoms[n++] = htole64(op->p_p->ps_fxtid);
	fxt_atoms[n++] = htole64(op->p_fxtid);
	fxt_atoms[n++] = htole64(np->p_p->ps_fxtid);
	fxt_atoms[n++] = htole64(np->p_fxtid);

	fxt_atoms[0] = htole64(FXT_T_SCHED | (n << FXT_H_SIZE_SHIFT));
	fxt_atoms[0] |= htole64((uint64_t)state->cpu << 16);
	fxt_atoms[0] |= htole64((uint64_t)ostate << 24);
//	fxt_atoms[0] |= htole64(oid << 28);
//	fxt_atoms[0] |= htole64(nid << 36);
	fxt_atoms[0] |= htole64(1ULL << 44);
	fxt_atoms[0] |= htole64(1ULL << 52);
	fxt_atoms[0] |= htole64((uint64_t)0 << 60);

	//fxt_write(fxt_atoms, n, ofile);
	fxt_insert(state->ns, fxt_atoms, n);

	state->p = np;
}

static void
lltx_sched_wake(struct lltstate *state, struct llevent *lle, uint64_t record,
    const uint64_t *extra, unsigned int extralen)
{
	unsigned int tid;
	struct llt_tid *p;
	size_t n;

	if (extralen > 0) {
		p = state->p;

		n = 1;
		fxt_atoms[n++] = htole64(state->ns);
		fxt_atoms[n++] = htole64(p->p_p->ps_fxtid);
		fxt_atoms[n++] = htole64(p->p_fxtid);

		fxt_atoms[0] = htole64(FXT_T_EVENT | (n << FXT_H_SIZE_SHIFT));
		fxt_atoms[0] |= htole64((uint64_t)0 << 16); /* instant event */
		fxt_atoms[0] |= htole64(0ULL << 20); /* number of args */
		fxt_atoms[0] |= htole64((uint64_t)lltx_strid_sched << 32);
		fxt_atoms[0] |= htole64((uint64_t)lltx_strid_wakeup << 48);

		//fxt_write(fxt_atoms, n, ofile);
		fxt_insert(state->ns, fxt_atoms, n);

		n = 1;
		fxt_atoms[n++] = htole64(state->ns);
		fxt_atoms[n++] = htole64(p->p_p->ps_fxtid);
		fxt_atoms[n++] = htole64(p->p_fxtid);
		fxt_atoms[n++] = htole64(extra[0]);

		fxt_atoms[0] = htole64(FXT_T_EVENT | (n << FXT_H_SIZE_SHIFT));
		fxt_atoms[0] |= htole64((uint64_t)8 << 16);
		fxt_atoms[0] |= htole64(0ULL << 20); /* number of args */
		fxt_atoms[0] |= htole64((uint64_t)lltx_strid_sched << 32);
		fxt_atoms[0] |= htole64((uint64_t)lltx_strid_wakeup << 48);

		//fxt_write(fxt_atoms, n, ofile);
		fxt_insert(state->ns, fxt_atoms, n);
	}

	tid = (record >> LLTRACE_SCHED_TID_SHIFT) &
	    LLTRACE_SCHED_TID_MASK;

	p = lltx_tid(tid);
	if (p->p_p == NULL)
		errx(1, "wakeup thread %u is unknown", tid);

	if (verbose >= 2) {
		printf("#ev %zu[%zu] %llu cpu %u pid %llu tid %llu "
		    "wakeup pid %llu tid %llu\n",
		    lle->block, lle->slot, state->ns, state->cpu,
		    state->p->p_p->ps_fxtid, state->p->p_fxtid,
		    p->p_p->ps_fxtid, p->p_fxtid);
	}

	n = 1;
	fxt_atoms[n++] = htole64(state->ns);
	fxt_atoms[n++] = htole64(p->p_fxtid);

	fxt_atoms[0] = htole64(FXT_T_SCHED | (n << FXT_H_SIZE_SHIFT));
	fxt_atoms[0] |= htole64((uint64_t)state->cpu << 20);
	fxt_atoms[0] |= htole64((uint64_t)2 << 60);

	//fxt_write(fxt_atoms, n, ofile);
	//fxt_insert(state->ns, fxt_atoms, n);
}

static void
lltx_idle(struct lltstate *state, struct llevent *lle, unsigned int phase)
{
	struct llt_tid *p = state->p;
	uint64_t iprio, oprio;
//	uint64_t oid, iid;
	size_t n;

	if (state->idle == phase)
		return;

	if (state->idletid != p->p_tid) {
		errx(1, "idle outside the idle thread %u, in %u",
		    state->idletid, p->p_tid);
	}
	if (p->p_p == NULL)
		errx(1, "idle thread %u is unknown", state->idletid);

	if (verbose >= 2) {
		printf("#ev %zu[%zu] %llu cpu %u pid %llu tid %llu idle %s\n",
		    lle->block, lle->slot, state->ns, state->cpu,
		    p->p_p->ps_fxtid, p->p_fxtid,
		    lltrace_event_phase_names[phase]);
	}

	n = 1;
	fxt_atoms[n++] = htole64(state->ns);

	switch (phase) {
	case LLTRACE_EVENT_PHASE_START:
		oprio = 1;
		fxt_atoms[n++] = htole64(p->p_p->ps_fxtid);
		fxt_atoms[n++] = htole64(p->p_fxtid);
		iprio = 0;
		fxt_atoms[n++] = htole64(0);
		fxt_atoms[n++] = htole64(0);
		break;
	case LLTRACE_EVENT_PHASE_END:
		oprio = 0;
		fxt_atoms[n++] = htole64(0);
		fxt_atoms[n++] = htole64(0);
		iprio = 1;
		fxt_atoms[n++] = htole64(p->p_p->ps_fxtid);
		fxt_atoms[n++] = htole64(p->p_fxtid);
		break;
	default:
		return;
	}

	fxt_atoms[0] = htole64(FXT_T_SCHED | (n << FXT_H_SIZE_SHIFT));
	fxt_atoms[0] |= htole64((uint64_t)state->cpu << 16);
	fxt_atoms[0] |= htole64((uint64_t)3 << 24);
	fxt_atoms[0] |= htole64(oprio << 44);
	fxt_atoms[0] |= htole64(iprio << 52);
	fxt_atoms[0] |= htole64((uint64_t)0 << 60);

	//fxt_write(fxt_atoms, n, ofile);
	fxt_insert(state->ns, fxt_atoms, n);

	state->idle = phase;
}

static void
lltx_event_count(struct lltstate *state, struct llevent *lle,
    unsigned int phase, const char *classnm, size_t classnmlen,
    uint64_t record)
{
	char tname[128];
	uint32_t t, v;
	const char *eventnm;
	size_t eventnmlen;
	size_t n, an;

	t = (record >> LLTRACE_COUNT_T_SHIFT) & LLTRACE_COUNT_T_MASK;
	if (t >= nitems(lltrace_count_type_names) ||
	    (eventnm = lltrace_count_type_names[t]) == NULL) {
		int rv;

		warnx("unknown count type class %u", t);

		rv = snprintf(tname, sizeof(tname), "count-type-%u", t);
		if (rv == -1)
			errx(1, "count event type name snprintf");
		eventnm = tname;
		eventnmlen = rv;
		if (classnmlen >= sizeof(tname))
			errx(1, "event class name too long");
	} else
		eventnmlen = strlen(eventnm);

	v = (record >> LLTRACE_COUNT_V_SHIFT);

	n = 1;
	fxt_atoms[n++] = htole64(state->ns);
	fxt_atoms[n++] = htole64(state->p->p_p->ps_fxtid);
	fxt_atoms[n++] = htole64(state->p->p_fxtid);
	n = strtoatoms(fxt_atoms, n, classnm, classnmlen);
	n = strtoatoms(fxt_atoms, n, eventnm, eventnmlen);

	an = n++;
	fxt_atoms[an] = htole64(2 | (1 << 4));
	fxt_atoms[an] |= htole64(lltx_strid_count << 16);
	fxt_atoms[an] |= htole64((uint64_t)v << 32);

	fxt_atoms[0] = htole64(FXT_T_EVENT | (n << FXT_H_SIZE_SHIFT));
	fxt_atoms[0] |= htole64(lltrace_event_phase_map[phase] << 16);
	fxt_atoms[0] |= htole64(1 << 20); /* 1 argument */
	fxt_atoms[0] |= htole64(((1<<15) | classnmlen) << 32);
	fxt_atoms[0] |= htole64(((1<<15) | eventnmlen) << 48);

	fxt_write(fxt_atoms, n, ofile);
}

static void
lltx_event(struct lltstate *state, struct llevent *lle, uint64_t record,
    const uint64_t *extra, unsigned int extralen)
{
	char cname[32], ename[128];
	unsigned int phase;
	unsigned int class;
	const char *classnm;
	size_t classnmlen;
	const char *eventnm;
	size_t eventnmlen;
	size_t n;

	phase = (record >> LLTRACE_EVENT_PHASE_SHIFT) &
	    LLTRACE_EVENT_PHASE_MASK;
	class = (record >> LLTRACE_EVENT_CLASS_SHIFT) &
	    LLTRACE_EVENT_CLASS_MASK;

	if (class >= nitems(lltrace_event_class_names) ||
	    (classnm = lltrace_event_class_names[class]) == NULL) {
		int rv;

		warnx("unknown event class %u", class);

		rv = snprintf(cname, sizeof(cname), "class-%u", class);
		if (rv == -1)
			errx(1, "event class name snprintf");
		classnm = cname;
		classnmlen = rv;
		if (classnmlen >= sizeof(cname))
			errx(1, "event class name too long");
	} else
		classnmlen = strlen(classnm);

	switch (class) {
	case LLTRACE_EVENT_CLASS_SCHED:
		if (verbose >= 2) {
			printf("#ev %zu[%zu] %llu cpu %u tid %llu sched\n",
			    lle->block, lle->slot, state->ns, state->cpu,
			    state->p->p_fxtid);
		}

		if (phase == LLTRACE_EVENT_PHASE_INSTANT)
			lltx_sched(state, lle, record, extra, extralen);
		return;
	case LLTRACE_EVENT_CLASS_WAKE:
		if (verbose >= 2) {
			printf("#ev %zu[%zu] %llu cpu %u tid %llu wake\n",
			    lle->block, lle->slot, state->ns, state->cpu,
			    state->p->p_fxtid);
		}
		lltx_sched_wake(state, lle, record, extra, extralen);
		return;
	case LLTRACE_EVENT_CLASS_IDLE:
		if (verbose >= 2) {
			printf("#ev %zu[%zu] %llu cpu %u tid %llu idle\n",
			    lle->block, lle->slot, state->ns, state->cpu,
			    state->p->p_fxtid);
		}
		lltx_idle(state, lle, phase);
		return;
	case LLTRACE_EVENT_CLASS_SYSCALL:
		{
			unsigned int code = (record >> LLTRACE_SYSCALL_SHIFT) &
			    LLTRACE_SYSCALL_MASK;
			eventnm = syscall_name(code);

			switch (code) {
			case SYS_exit:
			case SYS___threxit:
				phase = LLTRACE_EVENT_PHASE_INSTANT;
				break;
			}
		}
		eventnmlen = strlen(eventnm);
		break;
	case LLTRACE_EVENT_CLASS_INTR:
		{
			unsigned int type = (record >> LLTRACE_INTR_T_SHIFT) &
			    LLTRACE_INTR_T_MASK;
			eventnm = lltrace_intr_type_names[type];
		}
		eventnmlen = strlen(eventnm);
		break;
	case LLTRACE_EVENT_CLASS_FUNC: {
			uint32_t addr = record >> 32;
			const struct ksym *k = ksym_nfind(addr);
			if (k == NULL) {
				int rv = snprintf(ename, sizeof(ename),
				    "?+%x", addr);
				if (rv == -1)
					errx(1, "func name snprintf");
				eventnm = ename;
				eventnmlen = rv;
			} else {
				uint32_t diff = addr - k->addr;
				if (diff != 0) {
					int rv = snprintf(ename, sizeof(ename),
					    "%s+%x", k->name, diff);
					if (rv == -1)
						errx(1, "func name snprintf");
					eventnm = ename;
					eventnmlen = rv;
				} else {
					eventnm = k->name;
					eventnmlen = strlen(eventnm);
				}
			}
		}
		break;
	case LLTRACE_EVENT_CLASS_COUNT:
		lltx_event_count(state, lle, phase, classnm, classnmlen,
		    record);
		return;
		
	default:
		eventnm = classnm;
		eventnmlen = classnmlen;
		break;
	}

	if (verbose >= 2) {
		printf("#ev %zu[%zu] %llu cpu %u tid %llu %s:%s %s\n",
		    lle->block, lle->slot, state->ns, state->cpu,
		    state->p->p_fxtid,
		    classnm, eventnm, lltrace_event_phase_names[phase]);
	}

	n = 1;
	fxt_atoms[n++] = htole64(state->ns);
	fxt_atoms[n++] = htole64(state->p->p_p->ps_fxtid);
	fxt_atoms[n++] = htole64(state->p->p_fxtid);
	n = strtoatoms(fxt_atoms, n, classnm, classnmlen);
	n = strtoatoms(fxt_atoms, n, eventnm, eventnmlen);

	fxt_atoms[0] = htole64(FXT_T_EVENT | (n << FXT_H_SIZE_SHIFT));
	fxt_atoms[0] |= htole64(lltrace_event_phase_map[phase] << 16);
	fxt_atoms[0] |= htole64(((1<<15) | classnmlen) << 32);
	fxt_atoms[0] |= htole64(((1<<15) | eventnmlen) << 48);

	fxt_write(fxt_atoms, n, ofile);
}

static void
lltx_locking(struct lltstate *state, struct llevent *lle, uint64_t record,
    const uint64_t *extra, unsigned int extralen)
{
	struct llt_tid *p = state->p;
	unsigned int ltype;
	unsigned int lop;
	uint64_t cref;
	uint64_t nref;
//	uint64_t tref;
	uint64_t addr;
	size_t n;
	struct ksym *k;
	int durev = -1;
	unsigned int nargs = 1;

	ltype = (record >> LLTRACE_LK_TYPE_SHIFT) & LLTRACE_LK_TYPE_MASK;
	lop = (record >> LLTRACE_LK_PHASE_SHIFT) & LLTRACE_LK_PHASE_MASK;
	addr = record >> LLTRACE_LK_ADDR_SHIFT;

	cref = lltx_strids_locks[ltype];
	if (cref == 0) {
		warnx("unknown lock type %u", ltype);
		return;
	}
	nref = lltx_strids_lock_ops[lop];
	if (cref == 0) {
		warnx("unknown %s lock op %u", str_locks[ltype], lop);
		return;
	}

//	tref = lltx_thrid(state->p);

	switch (lop) {
	case LLTRACE_LK_A_START:
		durev = 2;
		break;
	case LLTRACE_LK_A_EXCL:
	case LLTRACE_LK_A_SHARED:
	case LLTRACE_LK_A_ABORT:
		durev = 3;
		break;
	}

	if (0 && ltype == LLTRACE_LK_RW && durev != -1) {
		n = 1;
		fxt_atoms[n++] = htole64(state->ns);
		fxt_atoms[n++] = htole64(p->p_p->ps_fxtid);
		fxt_atoms[n++] = htole64(p->p_fxtid);

		fxt_atoms[0] = htole64(FXT_T_EVENT | (n << FXT_H_SIZE_SHIFT));
		fxt_atoms[0] |= htole64((uint64_t)durev << 16); /* duration begin */
		fxt_atoms[0] |= htole64(cref << 32);
		fxt_atoms[0] |= htole64((uint64_t)lltx_strid_acquire << 48);

		//fxt_write(fxt_atoms, n, ofile);
		fxt_insert(state->ns, fxt_atoms, n);
	}

	k = ksym_nfind(addr);
	if (k != NULL && k->ref == 0) {
		k->ref = lltx_str(k->name);
#if 0

		n = 1;
		fxt_atoms[n++] = addr;

		fxt_atoms[0] = htole64(FXT_T_KOBJ | (n << FXT_H_SIZE_SHIFT));
		fxt_atoms[0] |= htole64(0ULL << 16); /* ZX_OBJ_TYPE_NONE */
		fxt_atoms[0] |= htole64(k->ref << 24); /* name */
		fxt_atoms[0] |= htole64(0ULL << 40); /* number of args */

		fxt_write(fxt_atoms, n, ofile);
#endif
	}

	if (verbose >= 2) {
		printf("#lk %zu[%zu] %llu cpu %u pid %llu tid %llu "
		    "%s %s\n",
		    lle->block, lle->slot, state->ns, state->cpu,
		    state->p->p_p->ps_fxtid, state->p->p_fxtid,
		    str_locks[ltype], str_lock_ops[lop]);
	}

	n = 1;
	fxt_atoms[n++] = htole64(state->ns);
	fxt_atoms[n++] = htole64(p->p_p->ps_fxtid);
	fxt_atoms[n++] = htole64(p->p_fxtid);
	fxt_atoms[n++] = htole64(8 | (2 << 4) | (cref << 16));
	fxt_atoms[n++] = htole64(addr);
	if (k != NULL) {
		size_t na = n++;
		uint32_t diff;

		fxt_atoms[na] = htole64(6 | (2 << 4));
		fxt_atoms[na] |= htole64((uint64_t)lltx_strid_symbol << 16);
		fxt_atoms[na] |= htole64((uint64_t)k->ref << 32);

		nargs++;

		diff = addr - k->addr;
		if (diff > 0) {
			na = n++;

			fxt_atoms[na] = htole64(2 | (1 << 4));
			fxt_atoms[na] |= htole64((uint64_t)lltx_strid_offset << 16);
			fxt_atoms[na] |= htole64((uint64_t)diff << 32);

			nargs++;
		} 
	}

	fxt_atoms[0] = htole64(FXT_T_EVENT | (n << FXT_H_SIZE_SHIFT));
	fxt_atoms[0] |= htole64(0 << 16); /* instant event */
	fxt_atoms[0] |= htole64(nargs << 20);
//	fxt_atoms[0] |= htole64(tref << 24);
	fxt_atoms[0] |= htole64(cref << 32);
	fxt_atoms[0] |= htole64(nref << 48);

	fxt_write(fxt_atoms, n, ofile);
}

#if 0
static void
lltextract_pc(struct llevent *lle, int event, uint64_t pc)
{
	lle->event = event;

	/*
         * XXX The PC sample is generated after the local_timer
         * interrupt, but we really want its sample time to be just
         * before that interrupt.
	 */

	/*
         * Put a hash of the PC name into arg, so HTML display can
         * choose colors quickly.
	 */
	lle->arg0 = (pc >> 6) & 0xffff;

	if (event == KUTRACE_PC_K) {
		const struct ksym *k;

		k = ksym_nfind(pc);
		if (k != NULL) {
			if (asprintf(&lle->name, "PC=%s", k->name) == -1)
				errx(1, "PC_K name asprintf");
			return;
		}
	}

	if (asprintf(&lle->name, "PC=%016llx", pc) == -1)
		errx(1, "PC asprintf");
}

static char *
xstrdup(const char *src)
{
	char *dst;

	dst = strdup(src);
	if (dst == NULL)
		err(1, "strdup %s", src);

	return (dst);
}

static void
lltx_event(const char *name, const char *cat, const char *ph,
    uint64_t ts, pid_t pid, pid_t tid)
{
	fprintf(ofile, "{");
	fprintf(ofile, "\"name\":\"%s\",\"cat\":\"%s\",\"ph\":\"%s\",",
	    name, cat, ph);
	fprintf(ofile, "\"ts\":%llu.%03llu,\"pid\":%d,\"tid\":%d",
	    ts / 1000, ts % 1000, pid, tid);
	fprintf(ofile, "},\n");
}

static char *
trap_name(unsigned int trap)
{
	const char *source;
	char *name;

	switch (trap) {
	case LLTRACE_TRAP_PAGEFAULT:
		source = "page_fault";
		break;
	default:
		if (asprintf(&name, "trap-%u", trap) == -1)
			errx(1, "trap asprintf");
		return (name);
	}

	name = xstrdup(source);

	return (name);
}

static void
lltextract_trap(struct lltstate *state, struct llevent *lle,
    unsigned int event, uint64_t v)
{
	unsigned int trap;

	trap = (v >> LLTRACE_ARG32_SHIFT) & LLTRACE_ARG32_MASK;

	lle->pid = state->pid;
	lle->tid = state->tid;
	lle->event = event + trap;
	lle->name = trap_name(trap);

	lltx_event(trap_name(trap), "trap", event == KUTRACE_TRAP ? "B" : "E",
	    state->ns, lle->pid, lle->tid);
}

static void
lltextract_sched(struct lltstate *state, struct llevent *lle,
    unsigned int event)
{
	lle->pid = state->pid;
	lle->tid = state->tid;
	lle->event = event;
	lle->arg0 = 0;
	lle->name = xstrdup("-sched-");

	lltx_event("sched", "sched", event == 0x9ff ? "B" : "E",
	    state->ns, lle->pid, lle->tid);
}

static void
lltextract_lock(struct lltstate *state, struct llevent *lle,
    unsigned int event, uint64_t v)
{
	unsigned int lock;

	lock = (v >> LLTRACE_ARG32_SHIFT) & LLTRACE_ARG32_MASK;
	lock &= 0xffff;

	lle->pid = state->pid;
	lle->tid = state->tid;
	lle->event = event;
	lle->arg0 = lock;

	if (asprintf(&lle->name, "lock.%x", lock) == -1)
		errx(1, "lock asprintf");
}

static void
lltextract_pkts(struct lltstate *state, struct llevent *lle, uint64_t v)
{
	unsigned int type = v & LLTRACE_PKTS_T_MASK;
	const char *name;

	switch (type) {
	case LLTRACE_PKTS_T_IFQ:
		name = "ifq";
		break;
	case LLTRACE_PKTS_T_NETTQ:
		name = "process";
		break;
	case LLTRACE_PKTS_T_IFIQ:
		name = "ifiq";
		break;
#ifdef LLTRACE_PKTS_T_DROP
	case LLTRACE_PKTS_T_DROP:
		name = "drop";
		break;
#endif
	default:
		errx(1, "unexpected pkts type %x",
		    type >> LLTRACE_PKTS_T_SHIFT);
		/* NOTREACHED */
	}

	lle->tid = state->tid;
	lle->event = KUTRACE_MARKA; /* sure */
	lle->arg0 = v;

	if (asprintf(&lle->name, "%s=%llu", name,
	    v & LLTRACE_PKTS_V_MASK) == -1)
		errx(1, "pkts asprintf");
}

static void
lltextract_func(struct lltstate *state, struct llevent *lle,
    unsigned int event, const char *evname, uint64_t v)
{
	const struct ksym *k;

	lle->arg0 = (v >> LLTRACE_ARG32_SHIFT) & LLTRACE_ARG32_MASK;

	lle->tid = state->tid;
	lle->event = event;

	k = ksym_nfind(lle->arg0);
	if (k != NULL) {
		uint32_t diff = lle->arg0 - k->addr;
		if (diff == 0) {
			if (asprintf(&lle->name, "%s=%s", evname,
			    k->name) == -1)
				err(1, "kfunc %s asprintf", evname);
		} else {
			if (asprintf(&lle->name, "%s=%s+%u", evname,
			    k->name, diff) == -1)
				err(1, "kfunc %s asprintf", evname);
		}
	} else {
		if (asprintf(&lle->name, "%s=0x%x", evname, lle->arg0) == -1)
			err(1, "kfunc %s asprintf", evname);
	}
}

static void
lltextract_mark(struct lltstate *state, struct llevent *lle,
    unsigned int ev, uint64_t v)
{

	switch (ev) {
	case LLTRACE_EVENT_IDLE:
		lle->event = KUTRACE_MWAIT;
		lle->arg0 = 255;

		lle->name = xstrdup("mwait");
		break;

	case LLTRACE_EVENT_RUNNABLE:
		lle->tid = state->tid;
		lle->event = KUTRACE_RUNNABLE;
		lle->arg0 = (v >> LLTRACE_ARG32_SHIFT) & LLTRACE_ARG32_MASK;
		lle->arg0 &= 0xffff;

		if (asprintf(&lle->name, "runnable.%u", lle->arg0) == -1)
			err(1, "runnable asprintf");
		break;

	case LLTRACE_EVENT_IPI:
		lle->tid = state->tid;
		lle->event = KUTRACE_IPI;
		lle->arg0 = (v >> LLTRACE_ARG32_SHIFT) & LLTRACE_ARG32_MASK;

		lle->name = xstrdup("sendipi");
		break;

	case LLTRACE_EVENT_SCHED:
		lltextract_sched(state, lle,
		    KUTRACE_SYSCALL(KUTRACE_SYSCALL_SCHED));
		break;
	case LLTRACE_EVENT_SCHEDRET:
		lltextract_sched(state, lle,
		    KUTRACE_SYSRET(KUTRACE_SYSCALL_SCHED));
		break;

	case LLTRACE_EVENT_TRAP:
		lltextract_trap(state, lle, KUTRACE_TRAP, v);
		break;
	case LLTRACE_EVENT_TRAPRET:
		lltextract_trap(state, lle, KUTRACE_TRAPRET, v);
		break;

	case LLTRACE_EVENT_LOCK(LLTRACE_LOCK_NOACQUIRE):
		lltextract_lock(state, lle, KUTRACE_LOCKNOACQUIRE, v);
		break;
	case LLTRACE_EVENT_LOCK(LLTRACE_LOCK_ACQUIRE):
		lltextract_lock(state, lle, KUTRACE_LOCKACQUIRE, v);
		break;
	case LLTRACE_EVENT_LOCK(LLTRACE_LOCK_WAKEUP):
		lltextract_lock(state, lle, KUTRACE_LOCKWAKEUP, v);
		break;

	case LLTRACE_EVENT_PKTS:
		lltextract_pkts(state, lle, v);
		break;

	case LLTRACE_EVENT_MARK:
		lle->tid = state->tid;
		lle->event = KUTRACE_MARKB;
		lle->arg0 = 0;

		lle->name = xstrdup("markd=yep");
		break;

	case LLTRACE_EVENT_KFUNC_ENTER:
		lltextract_func(state, lle, KUTRACE_MARKD, "enter", v);
		break;

	case LLTRACE_EVENT_KFUNC_LEAVE:
		lltextract_func(state, lle, KUTRACE_MARKD, "leave", v);
		break;

	default:
		errx(1, "unexpected mark event 0x%03x", ev);
		/* NOTREACHED */
	}
}

static char *
irq_name(unsigned int type, unsigned int vec)
{
	const char *source;
	char *name;

	switch (type) {
	case LLTRACE_IRQ_IPI:
		source = "ipi";
		break;
	case LLTRACE_IRQ_BOTTOM_HALF:
		if (vec == 0)
			return xstrdup("BH:timer");

		source = "BH";
		break;
	case LLTRACE_IRQ_LOCAL_TIMER:
		return xstrdup("local_timer_vector");
	default:
		if (asprintf(&name, "irq%u:%u", type, vec) == -1)
			errx(1, "irq asprintf");
		return (name);
	}

	if (asprintf(&name, "%s:%u", source, vec) == -1)
		errx(1, "irq %s asprintf", source);

	return (name);
}

static void
lltextract_irq(struct lltstate *state, struct llevent *lle,
    unsigned int ev, uint64_t v)
{
	unsigned int ret = ev & 0x100;
	unsigned int type = ev & 0xff;
	unsigned int vec = (v >> LLTRACE_ARG32_SHIFT) & LLTRACE_ARG32_MASK;

	lle->event = (ret ? KUTRACE_IRQRET : KUTRACE_IRQ) | type;
	lle->arg0 = vec;

	lle->name = irq_name(type, vec);
}

static void
lltextract_syscall(struct lltstate *state, struct llevent *lle,
    unsigned int ev, uint64_t v)
{
	unsigned int sc = LLTRACE_SYSCALL_MASK(ev);

	lle->pid = state->pid;
	lle->tid = state->tid;
	lle->event = KUTRACE_SYSCALL(sc);
	lle->arg0 = (v >> LLTRACE_ARG0_SHIFT) & LLTRACE_ARG0_MASK;
	lle->name = syscall_name(sc);

	lltx_event(syscall_name(sc), "syscall", "B",
	    state->ns, lle->pid, lle->tid);
}

static void
lltextract_sysret(struct lltstate *state, struct llevent *lle,
    unsigned int ev, uint64_t v)
{
	unsigned int sc = LLTRACE_SYSCALL_MASK(ev);

	lle->pid = state->pid;
	lle->tid = state->tid;
	lle->event = KUTRACE_SYSRET(sc);
	lle->arg0 = (v >> LLTRACE_ARG0_SHIFT) & LLTRACE_ARG0_MASK; 
	lle->name = syscall_name(sc);

	lltx_event(syscall_name(sc), "syscall", "E",
	    state->ns, lle->pid, lle->tid);
}
#endif

RBT_GENERATE(llt_pid_tree, llt_pid, ps_entry, llt_pid_cmp);
RBT_GENERATE(llt_tid_tree, llt_tid, p_entry, llt_tid_cmp);

static inline int
lltx_fxt_record_cmp(const struct lltx_fxt_record *a,
    const struct lltx_fxt_record *b)
{
	if (a->ts > b->ts)
		return (1);
	if (a->ts < b->ts)
		return (-1);
	return (0);
}

HEAP_GENERATE(lltx_fxt_heap, lltx_fxt_record, entry, lltx_fxt_record_cmp);
