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

#ifndef _SYS_LLTRACE_H_
#define _SYS_LLTRACE_H_

/*
 * lltrace is heavily based KUTrace (kernel/userland tracing) by
 * Richard L. Sites.
 */

#define LLTRACE_NSLOTS		8192

struct lltrace_buffer {
	uint64_t		llt_slots[LLTRACE_NSLOTS];
};

#define LLTIOCSTART		_IO('t',128)
#define LLTIOCSTOP		_IO('t',129)
#define LLTIOCFLUSH		_IO('t',130)

/*
 * trace until all the buffers are used, or trace and reuse buffers.
 */
#define LLTRACE_MODE_HEAD		0
#define LLTRACE_MODE_TAIL		1
#define LLTRACE_MODE_COUNT		2

#define LLTIOCSMODE		_IOW('t', 131, unsigned int)
#define LLTIOCGMODE		_IOR('t', 131, unsigned int)

/*
 * how much memory in MB to allocate for lltrace_buffer structs
 * during tracing.
 */

#define LLTRACE_BLEN_MIN		1
#define LLTRACE_BLEN_MAX		256

#define LLTIOCSBLEN		_IOW('t', 132, unsigned int)
#define LLTIOCGBLEN		_IOR('t', 132, unsigned int)

/*
 * lltrace collects kernel events in per-CPU buffers.
 */

/*
 * The first 8 words of the per-CPU buffer are dedicated to metadata
 * about the CPU and the period of time over which events were
 * collected.
 */

struct lltrace_header {
	/* slots[0] */
	uint32_t		h_cpu;
	uint32_t		h_idletid;

	/* slots[1] */
	uint64_t		h_boottime;

	/* slots[2] */
	uint64_t		h_start_cy;
	/* slots[3] */
	uint64_t		h_start_ns;
	/* slots[4] */
	uint64_t		h_end_cy;
	/* slots[5] */
	uint64_t		h_end_ns;

	/* slots[6] */
	uint32_t		h_pid;
	uint32_t		h_tid;
	/* slots[7] */
	uint64_t		h_zero;
};

#define LLTRACE_MASK(_w) ((1ULL << (_w)) - 1)

#define LLTRACE_TYPE_SHIFT	0
#define LLTRACE_TYPE_WIDTH	3
#define LLTRACE_TYPE_MASK	LLTRACE_MASK(LLTRACE_TYPE_WIDTH)

#define LLTRACE_TYPE_ID		0x0ULL
#define LLTRACE_TYPE_EVENT	0x1ULL
#define LLTRACE_TYPE_LOCKING	0x2ULL

#define LLTRACE_LEN_SHIFT	(LLTRACE_TYPE_SHIFT + LLTRACE_TYPE_WIDTH)
#define LLTRACE_LEN_WIDTH	3
#define LLTRACE_LEN_MASK	LLTRACE_MASK(LLTRACE_LEN_WIDTH)

/* most records have a timestamp */
#define LLTRACE_TS_TYPES	( \
				    (1 << LLTRACE_TYPE_EVENT) | \
				    (1 << LLTRACE_TYPE_LOCKING) \
				)

#define LLTRACE_TS_SHIFT	(LLTRACE_LEN_SHIFT + LLTRACE_LEN_WIDTH)
#define LLTRACE_TS_WIDTH	20
#define LLTRACE_TS_MASK		LLTRACE_MASK(20)

/*
 * id records
 */

/* tid record contains pid and kthread flag, followed by proc name */
#define LLTRACE_ID_TYPE_SHIFT	(LLTRACE_LEN_SHIFT + LLTRACE_LEN_WIDTH)
#define LLTRACE_ID_TYPE_WIDTH	6
#define LLTRACE_ID_TYPE_MASK	LLTRACE_MASK(3)
#define LLTRACE_ID_TYPE_TID	0x0

#define LLTRACE_ID_TID_SHIFT	(LLTRACE_ID_TYPE_SHIFT + LLTRACE_ID_TYPE_WIDTH)
#define LLTRACE_ID_TID_WIDTH	20 /* >= than 19 bit TID_MASK */
#define LLTRACE_ID_TID_MASK	LLTRACE_MASK(LLTRACE_ID_TID_WIDTH)

#define LLTRACE_ID_TID_PID_SHIFT	32
#define LLTRACE_ID_TID_PID_WIDTH	20 /* >= whatever kernel pid range is */
#define LLTRACE_ID_TID_PID_MASK		LLTRACE_MASK(LLTRACE_ID_TID_PID_WIDTH)
#define LLTRACE_ID_TID_SYSTEM	(1ULL << 63) /* kernel thread */

/*
 * event records
 */

#define LLTRACE_EVENT_PHASE_SHIFT	(LLTRACE_TS_SHIFT + LLTRACE_TS_WIDTH)
#define LLTRACE_EVENT_PHASE_WIDTH	2
#define LLTRACE_EVENT_PHASE_MASK	LLTRACE_MASK(LLTRACE_EVENT_PHASE_WIDTH)
#define LLTRACE_EVENT_PHASE_INSTANT	0x0
#define LLTRACE_EVENT_PHASE_START	0x1
#define LLTRACE_EVENT_PHASE_STEP	0x2
#define LLTRACE_EVENT_PHASE_END		0x3

#define LLTRACE_EVENT_CLASS_WIDTH	4
#define LLTRACE_EVENT_CLASS_SHIFT	\
    (LLTRACE_EVENT_PHASE_SHIFT + LLTRACE_EVENT_PHASE_WIDTH)
#define LLTRACE_EVENT_CLASS_MASK	LLTRACE_MASK(LLTRACE_EVENT_CLASS_WIDTH)
#define LLTRACE_EVENT_CLASS_SYSCALL	0
#define LLTRACE_EVENT_CLASS_IDLE	1
#define LLTRACE_EVENT_CLASS_PAGEFAULT	2
#define LLTRACE_EVENT_CLASS_INTR	3
#define LLTRACE_EVENT_CLASS_SCHED	4
#define LLTRACE_EVENT_CLASS_FUNC	5
#define LLTRACE_EVENT_CLASS_WAKE	6
#define LLTRACE_EVENT_CLASS_COUNT	7

#define LLTRACE_EVENT_DATA_SHIFT	\
    (LLTRACE_EVENT_CLASS_SHIFT + LLTRACE_EVENT_CLASS_WIDTH)
#define LLTRACE_EVENT_DATA_SHIFT_CHECK	32

#define LLTRACE_SYSCALL_SHIFT		LLTRACE_EVENT_DATA_SHIFT
#define LLTRACE_SYSCALL_WIDTH		10
#define LLTRACE_SYSCALL_MASK		LLTRACE_MASK(LLTRACE_SYSCALL_WIDTH)

#define LLTRACE_SCHED_TID_SHIFT		LLTRACE_EVENT_DATA_SHIFT
#define LLTRACE_SCHED_TID_WIDTH		LLTRACE_ID_TID_WIDTH
#define LLTRACE_SCHED_TID_MASK		LLTRACE_MASK(LLTRACE_SCHED_TID_WIDTH)
#define LLTRACE_SCHED_STATE_SHIFT	\
    (LLTRACE_EVENT_DATA_SHIFT + LLTRACE_ID_TID_WIDTH)
#define LLTRACE_SCHED_STATE_WIDTH	4
#define LLTRACE_SCHED_STATE_MASK	LLTRACE_MASK(LLTRACE_SCHED_STATE_WIDTH)
#define LLTRACE_SCHED_STATE_NEW		0
#define LLTRACE_SCHED_STATE_RUNNING	1
#define LLTRACE_SCHED_STATE_SUSPENDED	2
#define LLTRACE_SCHED_STATE_BLOCKED	3
#define LLTRACE_SCHED_STATE_DYING	4
#define LLTRACE_SCHED_STATE_DEAD	5

#define LLTRACE_SYSCALL_V_SHIFT		\
    (LLTRACE_SYSCALL_SHIFT + LLTRACE_SYSCALL_WIDTH)

#define LLTRACE_INTR_T_SHIFT		LLTRACE_EVENT_DATA_SHIFT
#define LLTRACE_INTR_T_WIDTH		2
#define LLTRACE_INTR_T_MASK		LLTRACE_MASK(LLTRACE_INTR_T_WIDTH)
#define LLTRACE_INTR_T_HW		0ULL
#define LLTRACE_INTR_T_SW		1ULL
#define LLTRACE_INTR_T_IPI		2ULL
#define LLTRACE_INTR_T_CLOCK		3ULL

#define LLTRACE_INTR_DATA_SHIFT		\
    (LLTRACE_INTR_T_SHIFT + LLTRACE_INTR_T_WIDTH)

/* record a count of something */
#define LLTRACE_COUNT_T_SHIFT		LLTRACE_EVENT_DATA_SHIFT
#define LLTRACE_COUNT_T_WIDTH		8
#define LLTRACE_COUNT_T_MASK		LLTRACE_MASK(LLTRACE_COUNT_T_WIDTH)

#define LLTRACE_COUNT_T_PKTS_IFIQ	0
#define LLTRACE_COUNT_T_PKTS_NETTQ	1
#define LLTRACE_COUNT_T_PKTS_IFQ	2
#define LLTRACE_COUNT_T_PKTS_QDROP	3
#define LLTRACE_COUNT_T_PKTS_HDROP	4

#define LLTRACE_COUNT_V_SHIFT		\
    (LLTRACE_COUNT_T_SHIFT + LLTRACE_COUNT_T_WIDTH)

/*
 * locking records
 */

#define LLTRACE_LK_TYPE_SHIFT		(LLTRACE_TS_SHIFT + LLTRACE_TS_WIDTH)
#define LLTRACE_LK_TYPE_WIDTH		2
#define LLTRACE_LK_TYPE_MASK		LLTRACE_MASK(LLTRACE_LK_TYPE_WIDTH)
#define LLTRACE_LK_RW			0x0
#define LLTRACE_LK_MTX			0x1
#define LLTRACE_LK_K			0x2
 
#define LLTRACE_LK_PHASE_SHIFT		\
    (LLTRACE_LK_TYPE_SHIFT + LLTRACE_LK_TYPE_WIDTH)
#define LLTRACE_LK_PHASE_WIDTH		4
#define LLTRACE_LK_PHASE_MASK		LLTRACE_MASK(LLTRACE_LK_PHASE_WIDTH)
#define LLTRACE_LK_I_EXCL		0x0 /* instantly got wr lock */
#define LLTRACE_LK_I_SHARED		0x1 /* instantly got rd lock */
#define LLTRACE_LK_A_START		0x2 /* acquiring lock */
#define LLTRACE_LK_A_EXCL		0x3 /* acquired wr lock */
#define LLTRACE_LK_A_SHARED		0x4 /* acquired rd lock */
#define LLTRACE_LK_A_ABORT		0x5 /* acquire aborted */
#define LLTRACE_LK_DOWNGRADE		0x6 /* wr to rd lock */
#define LLTRACE_LK_R_EXCL		0x7 /* released wr lock */
#define LLTRACE_LK_R_SHARED		0x8 /* released rd lock */
#define LLTRACE_LK_I_FAIL		0x9 /* try failed */

#define LLTRACE_LK_ADDR_SHIFT		\
    (LLTRACE_LK_PHASE_SHIFT + LLTRACE_LK_PHASE_WIDTH)

#ifdef _KERNEL

struct lltrace_cpu;

static inline struct lltrace_cpu *
lltrace_enter_spc(struct schedstate_percpu *spc)
{
	return (READ_ONCE(spc->spc_lltrace));
}

static inline struct lltrace_cpu *
lltrace_enter_cpu(struct cpu_info *ci)
{
	return lltrace_enter_spc(&ci->ci_schedstate);
}

static inline struct lltrace_cpu *
lltrace_enter(void)
{
	return lltrace_enter_cpu(curcpu());
}

void	lltrace_idle(struct lltrace_cpu *, unsigned int);
void	lltrace_statclock(struct lltrace_cpu *, int, unsigned long);

void	lltrace_syscall(struct lltrace_cpu *, register_t,
	    size_t, const register_t *);
void	lltrace_sysret(struct lltrace_cpu *, register_t,
	    int, const register_t [2]);
struct lltrace_cpu *
	lltrace_pidname(struct lltrace_cpu *, struct proc *);
void	lltrace_switch(struct lltrace_cpu *, struct proc *, struct proc *);
void	lltrace_sched_enter(struct lltrace_cpu *);
void	lltrace_sched_leave(struct lltrace_cpu *);
void	lltrace_runnable(struct lltrace_cpu *, struct proc *);

void	lltrace_event_start(struct lltrace_cpu *, unsigned int);
void	lltrace_event_end(struct lltrace_cpu *, unsigned int);
void	lltrace_count(struct lltrace_cpu *, unsigned int, unsigned int);

void	lltrace_lock(struct lltrace_cpu *, void *, unsigned int, unsigned int);

void	lltrace_pkts(struct lltrace_cpu *, unsigned int, unsigned int);
void	lltrace_mark(struct lltrace_cpu *);

void	lltrace_fn_enter(struct lltrace_cpu *, void *);
void	lltrace_fn_leave(struct lltrace_cpu *, void *);

/* MD bits */

void	lltrace_ipi(struct lltrace_cpu *, unsigned int);
#define lltrace_ipi_bcast(_llt) lltrace_ipi((_llt), ~0U);

void	lltrace_intr_enter(struct lltrace_cpu *, unsigned int, unsigned int);
void	lltrace_intr_leave(struct lltrace_cpu *, unsigned int, unsigned int);

#endif /* _KERNEL */

#endif /* _SYS_LLTRACE_H_ */
