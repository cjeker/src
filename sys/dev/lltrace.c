/* $OpenBSD$ */

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
 * This code was written by David Gwynne <dlg@uq.edu.au> as part
 * of the Information Technology Infrastructure Group (ITIG) in the
 * Faculty of Engineering, Architecture and Information Technology
 * (EAIT).
 *
 * It was heavily inspired by the KUTrace (kernel/userland tracing)
 * framework by Richard L. Sites.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/task.h>
#include <sys/time.h>
#include <sys/smr.h>

#include <sys/proc.h>
#include <sys/sched.h>

#include <sys/lltrace.h>

#if defined(__amd64__) || defined(__i386__)

static inline unsigned int
lltrace_cas(unsigned int *p, unsigned int e, unsigned int n)
{
	__asm volatile("cmpxchgl %2, %1"
	    : "=a" (e), "=m" (*p)
	    : "r" (n), "a" (e), "m" (*p));

	return (e);
}

static inline uint64_t
lltrace_ts(void)
{
	unsigned int hi, lo;

	__asm volatile("lfence; rdtsc" : "=d" (hi), "=a" (lo));

	return (lo & (LLTRACE_TS_MASK << LLTRACE_TS_SHIFT));
}

static inline uint64_t
lltrace_ts_long(void)
{
	return (rdtsc_lfence() & ~LLTRACE_MASK(LLTRACE_TS_SHIFT));
}

#elif defined(__aarch64__)

#define lltrace_cas(_p, _e, _n) atomic_cas_uint((_p), (_e), (_n))

static inline uint64_t
lltrace_ts_long(void)
{
	uint64_t ts;

	__asm volatile("mrs %x0, cntvct_el0" : "=r" (ts));

	return (ts << LLTRACE_TS_SHIFT);
}

static inline uint64_t
lltrace_ts(void)
{
	uint64_t ts = ltrace_ts_long();

	return (ts & (LLTRACE_TS_MASK << LLTRACE_TS_SHIFT));
}

#elif defined(__sparc64__)

#define lltrace_cas(_p, _e, _n) atomic_cas_uint((_p), (_e), (_n))

static inline uint64_t
lltrace_ts_long(void)
{
	uint64_t ts;

	ts = sys_tick();

	return (ts << LLTRACE_TS_SHIFT);
}

static inline uint64_t
lltrace_ts(void)
{
	uint64_t ts = lltrace_ts_long();

	return (ts & (LLTRACE_TS_MASK << LLTRACE_TS_SHIFT));
}

#else /* not x86 or arm64 */

#error not supported (yet)

static unsigned int
lltrace_cas(unsigned int *p, unsigned int e, unsigned int n)
{
	unsigned int o;
	int s;

	s = intr_disable();
	o = *p;
	if (o == e)
		*p = n;
	intr_restore(s);

	return (o);
}

static inline uint64_t
lltrace_ts(void)
{
	return (countertime());
}

static inline uint64_t
lltrace_ts_long(void)
{
	return (countertime());
}

#endif

#define LLTRACE_MB2NBUF(_mb) \
	(((_mb) * (1U << 20)) / sizeof(struct lltrace_buffer))
#define LLTRACE_NBUF2MB(_nbuf) \
	(((_nbuf) * sizeof(struct lltrace_buffer)) / (1U << 20))

#define LLTRACE_BLEN_DEFAULT	 16

struct lltrace_cpu {
	SIMPLEQ_ENTRY(lltrace_cpu)
				 llt_entry;
	struct lltrace_buffer	 llt_buffer;
	unsigned int		 llt_slot;
	unsigned int		 llt_pid;
	unsigned int		 llt_tid;
	uint64_t		 llt_wakeid;
};

SIMPLEQ_HEAD(lltrace_cpu_list, lltrace_cpu);

struct lltrace_softc {
	unsigned int		  sc_running;
	unsigned int		  sc_mode;
	struct rwlock		  sc_lock;
	unsigned int		  sc_nbuffers;

	unsigned int		  sc_free;
	unsigned int		  sc_used;
	struct lltrace_cpu	**sc_ring;
	struct lltrace_cpu	 *sc_buffers;

	unsigned int		  sc_read;
	unsigned int		  sc_reading;
	struct selinfo		  sc_sel;

	uint64_t		  sc_boottime;
	uint64_t		  sc_monotime;
};

static int	lltrace_start(struct lltrace_softc *, struct proc *);
static int	lltrace_stop(struct lltrace_softc *, struct proc *);
static int	lltrace_flush(struct lltrace_softc *);

static struct lltrace_softc *lltrace_sc;

int
lltattach(int num)
{
	return (0);
}

int
lltraceopen(dev_t dev, int flag, int mode, struct proc *p)
{
	struct lltrace_softc *sc;
	int error;

	if (minor(dev) != 0)
		return (ENXIO);

	error = suser(p);
	if (error != 0)
		return (error);

	if (lltrace_sc != NULL)
		return (EBUSY);

	sc = malloc(sizeof(*sc), M_DEVBUF, M_WAITOK|M_CANFAIL|M_ZERO);
	if (sc == NULL)
		return (ENOMEM);

	sc->sc_running = 0;
	sc->sc_nbuffers = LLTRACE_MB2NBUF(LLTRACE_BLEN_DEFAULT);

	rw_init(&sc->sc_lock, "lltlk");

	sc->sc_read = 0;
	sc->sc_reading = 0;
	klist_init_rwlock(&sc->sc_sel.si_note, &sc->sc_lock);

	/* commit */
	if (atomic_cas_ptr(&lltrace_sc, NULL, sc) != NULL) {
		free(sc, M_DEVBUF, sizeof(*sc));
		return (EBUSY);
	}

	return (0);
}

int
lltraceclose(dev_t dev, int flag, int mode, struct proc *p)
{
	struct lltrace_softc *sc = lltrace_sc;

	rw_enter_write(&sc->sc_lock);
	lltrace_stop(sc, p);
	lltrace_flush(sc);
	rw_exit_write(&sc->sc_lock);

	lltrace_sc = NULL;
	membar_sync();

	free(sc, M_DEVBUF, sizeof(*sc));

	return (0);
}

static int
lltrace_fionread(struct lltrace_softc *sc)
{
	int canread;

	rw_enter_read(&sc->sc_lock);
	canread = !sc->sc_running && (sc->sc_buffers != NULL) &&
	    (sc->sc_read < sc->sc_nbuffers);
	rw_exit_read(&sc->sc_lock);

	return (canread ? sizeof(struct lltrace_buffer) : 0);
}

static void
lltrace_cpu_init(struct lltrace_cpu *llt, struct lltrace_softc *sc,
    struct cpu_info *ci, unsigned int pid, unsigned int tid, uint64_t wakeid)
{
	struct lltrace_header *llh;

	llh = (struct lltrace_header *)&llt->llt_buffer;
	llh->h_cpu = cpu_number();
	llh->h_idletid = ci->ci_schedstate.spc_idleproc->p_tid;
	llh->h_boottime = sc->sc_boottime;
	llh->h_start_cy = lltrace_ts_long();
	llh->h_start_ns = nsecuptime() - sc->sc_monotime;
	llh->h_end_cy = 0;
	llh->h_end_ns = 0;
	llh->h_pid = pid;
	llh->h_tid = tid;
	llh->h_zero = 0;

	llt->llt_pid = pid;
	llt->llt_tid = tid;
	llt->llt_slot = 8;
	llt->llt_wakeid = wakeid;
}

static void
lltrace_cpu_fini(struct lltrace_cpu *llt, struct lltrace_softc *sc)
{
	struct lltrace_header *llh;

	llh = (struct lltrace_header *)&llt->llt_buffer;
	llh->h_end_cy = lltrace_ts_long();
	llh->h_end_ns = nsecuptime() - sc->sc_monotime;
}

static int
lltrace_set_mode(struct lltrace_softc *sc, unsigned int mode)
{
	int error;

	if (mode >= LLTRACE_MODE_COUNT)
		return (EINVAL);

	error = rw_enter(&sc->sc_lock, RW_WRITE|RW_INTR);
	if (error != 0)
		return (error);

	if (sc->sc_running)
		error = EBUSY;
	else
		sc->sc_mode = mode;

	rw_exit(&sc->sc_lock);
	return (error);
}

static int
lltrace_set_blen(struct lltrace_softc *sc, unsigned int blen)
{
	int error;
	unsigned int nbuffers;

	if (blen < LLTRACE_BLEN_MIN || blen > LLTRACE_BLEN_MAX)
		return (EINVAL);

	/* convert megabytes to the number of buffers */
	nbuffers = LLTRACE_MB2NBUF(blen);
	if (nbuffers <= ncpus)
		return (EINVAL);

	error = rw_enter(&sc->sc_lock, RW_WRITE|RW_INTR);
	if (error != 0)
		return (error);

	if (sc->sc_buffers != NULL)
		error = EBUSY;
	else
		sc->sc_nbuffers = nbuffers;

	rw_exit(&sc->sc_lock);
	return (error);
}

static int
lltrace_start(struct lltrace_softc *sc, struct proc *p)
{
	struct process *ps = p->p_p;
	struct bintime boottime;
	unsigned int i;
	size_t sz;
	struct lltrace_cpu_list l = SIMPLEQ_HEAD_INITIALIZER(l);
	struct lltrace_cpu *llt;
	struct cpu_info *ci;
	CPU_INFO_ITERATOR cii;
	unsigned int pid, tid;

	if (sc->sc_running)
		return EINVAL;

	if (sc->sc_nbuffers <= (ncpus * 2 + 1))
		return (EINVAL);

	lltrace_flush(sc);

	sc->sc_monotime = nsecuptime();

	binboottime(&boottime);
	sc->sc_boottime = BINTIME_TO_NSEC(&boottime) + sc->sc_monotime;

	sz = roundup(sc->sc_nbuffers * sizeof(*sc->sc_buffers), PAGE_SIZE);
	sc->sc_buffers = km_alloc(sz, &kv_any, &kp_dirty, &kd_waitok);
	if (sc->sc_buffers == NULL)
		return (ENOMEM);
	sc->sc_ring = mallocarray(sc->sc_nbuffers, sizeof(*sc->sc_ring),
	    M_DEVBUF, M_WAITOK);
	for (i = 0; i < sc->sc_nbuffers; i++) {
		llt = &sc->sc_buffers[i];
		llt->llt_slot = 0;
		sc->sc_ring[i] = llt;
	}

	sc->sc_free = 0; /* next slot to pull a free buffer from */
	sc->sc_used = 0; /* next slot to put a used buffer in */

	CPU_INFO_FOREACH(cii, ci) {
		i = sc->sc_free++; /* can't wrap yet */

		llt = sc->sc_ring[i];
		sc->sc_ring[i] = NULL;

		SIMPLEQ_INSERT_HEAD(&l, llt, llt_entry);
	}

	tid = p->p_tid;
	pid = ps->ps_pid;
	if (ISSET(ps->ps_flags, PS_SYSTEM))
		pid |= (1U << 31);

	CPU_INFO_FOREACH(cii, ci) {
		sched_peg_curproc(ci);

		llt = SIMPLEQ_FIRST(&l);
		SIMPLEQ_REMOVE_HEAD(&l, llt_entry);

		lltrace_cpu_init(llt, sc, ci, pid, tid, 0x1);
		lltrace_pidname(llt, p);

		membar_producer();
		ci->ci_schedstate.spc_lltrace = llt;
	}
	atomic_clearbits_int(&p->p_flag, P_CPUPEG);

	sc->sc_running = 1;

	return (0);
}

static int
lltrace_stop(struct lltrace_softc *sc, struct proc *p)
{
	struct lltrace_cpu *llt;
	struct cpu_info *ci;
	CPU_INFO_ITERATOR cii;
	unsigned long s;

	if (!sc->sc_running)
		return (EALREADY);

	sc->sc_running = 0;

	/* visit each cpu to take llt away safely */
	CPU_INFO_FOREACH(cii, ci) {
		sched_peg_curproc(ci);

		s = intr_disable();
		llt = ci->ci_schedstate.spc_lltrace;
		ci->ci_schedstate.spc_lltrace = NULL;
		intr_restore(s);

		lltrace_cpu_fini(llt, sc);
	}
	atomic_clearbits_int(&p->p_flag, P_CPUPEG);

	return (0);
}

static int
lltrace_flush(struct lltrace_softc *sc)
{
	size_t sz;

	rw_assert_wrlock(&sc->sc_lock);
	if (sc->sc_running)
		return (EBUSY);

	if (sc->sc_buffers == NULL)
		return (0);

	sz = roundup(sc->sc_nbuffers * sizeof(*sc->sc_buffers), PAGE_SIZE);
	km_free(sc->sc_buffers, sz, &kv_any, &kp_dirty);
	free(sc->sc_ring, M_DEVBUF, sc->sc_nbuffers * sizeof(*sc->sc_ring));

	sc->sc_buffers = NULL;
	sc->sc_ring = NULL;
	sc->sc_read = 0;

	return (0);
}

int
lltraceioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	struct lltrace_softc *sc = lltrace_sc;
	int error = 0;

	KERNEL_UNLOCK();

	switch (cmd) {
	case FIONREAD:
		*(int *)data = lltrace_fionread(sc);
		break;
	case FIONBIO:
		/* vfs tracks this for us if we let it */
		break;

	case LLTIOCSTART:
		error = rw_enter(&sc->sc_lock, RW_WRITE|RW_INTR);
		if (error != 0)
			break;
		error = lltrace_start(sc, p);
		rw_exit(&sc->sc_lock);
		break;
	case LLTIOCSTOP:
		error = rw_enter(&sc->sc_lock, RW_WRITE|RW_INTR);
		if (error != 0)
			break;
		error = lltrace_stop(sc, p);
		rw_exit(&sc->sc_lock);
		break;
	case LLTIOCFLUSH:
		error = rw_enter(&sc->sc_lock, RW_WRITE|RW_INTR);
		if (error != 0)
			break;
		error = lltrace_flush(sc);
		rw_exit(&sc->sc_lock);
		break;

	case LLTIOCSBLEN:
		error = lltrace_set_blen(sc, *(unsigned int *)data);
		break;
	case LLTIOCGBLEN:
		*(unsigned int *)data = LLTRACE_NBUF2MB(sc->sc_nbuffers);
		break;

	case LLTIOCSMODE:
		error = lltrace_set_mode(sc, *(unsigned int *)data);
		break;
	case LLTIOCGMODE:
		*(unsigned int *)data = sc->sc_mode;
		break;

	default:
		error = ENOTTY;
		break;
	}

	KERNEL_LOCK();

	return (error);
}

int
lltraceread(dev_t dev, struct uio *uio, int ioflag)
{
	struct lltrace_softc *sc = lltrace_sc;
	struct lltrace_cpu *llt;
	unsigned int slot;
	int error;

	KERNEL_UNLOCK();

	error = rw_enter(&sc->sc_lock, RW_WRITE|RW_INTR);
	if (error != 0)
		goto lock;

	if (sc->sc_running) {
		if (ISSET(ioflag, IO_NDELAY)) {
			error = EWOULDBLOCK;
			goto unlock;
		}

		do {
			sc->sc_reading++;
			error = rwsleep_nsec(&sc->sc_reading, &sc->sc_lock,
			    PRIBIO|PCATCH, "lltread", INFSLP);
			sc->sc_reading--;
			if (error != 0)
				goto unlock;
		} while (sc->sc_running);
	}

	if (sc->sc_buffers == NULL) {
		error = 0;
		goto unlock;
	}

	slot = sc->sc_read;
	for (;;) {
		if (slot >= sc->sc_nbuffers) {
			error = 0;
			goto unlock;
		}

		llt = &sc->sc_buffers[slot];
		KASSERT(llt->llt_slot <= nitems(llt->llt_buffer.llt_slots));
		if (llt->llt_slot > 0)
			break;

		slot++;
	}

	error = uiomove(&llt->llt_buffer,
	    llt->llt_slot * sizeof(llt->llt_buffer.llt_slots[0]), uio);
	if (error != 0)
		goto unlock;

	sc->sc_read = slot + 1;

unlock:
	rw_exit(&sc->sc_lock);
lock:
	KERNEL_LOCK();
	return (error);
}

static void
lltrace_filt_detach(struct knote *kn)
{
	struct lltrace_softc *sc = kn->kn_hook;

	klist_remove(&sc->sc_sel.si_note, kn);
}

static int
lltrace_filt_event(struct knote *kn, long hint)
{
	struct lltrace_softc *sc = kn->kn_hook;
	int canread;

	canread = !sc->sc_running && (sc->sc_buffers != NULL) &&
	    (sc->sc_read < sc->sc_nbuffers);

	kn->kn_data = canread ? sizeof(struct lltrace_buffer) : 0;

	return (canread);
}

static int
lltrace_filt_modify(struct kevent *kev, struct knote *kn)
{
	struct lltrace_softc *sc = kn->kn_hook;
	int active;

	rw_enter_write(&sc->sc_lock);
	active = knote_modify_fn(kev, kn, lltrace_filt_event);
	rw_exit_write(&sc->sc_lock);

	return (active);
}

static int
lltrace_filt_process(struct knote *kn, struct kevent *kev)
{
	struct lltrace_softc *sc = kn->kn_hook;
	int active;

	rw_enter_write(&sc->sc_lock);
	active = knote_process_fn(kn, kev, lltrace_filt_event);
	rw_exit_write(&sc->sc_lock);

	return (active);
}

static const struct filterops lltrace_filtops = {
	.f_flags	= FILTEROP_ISFD | FILTEROP_MPSAFE,
	.f_attach	= NULL,
	.f_detach	= lltrace_filt_detach,
	.f_event	= lltrace_filt_event,
	.f_modify	= lltrace_filt_modify,
	.f_process	= lltrace_filt_process,
};

int
lltracekqfilter(dev_t dev, struct knote *kn)
{
	struct lltrace_softc *sc = lltrace_sc;
	struct klist *klist;

	switch (kn->kn_filter) {
	case EVFILT_READ:
		klist = &sc->sc_sel.si_note;
		kn->kn_fop = &lltrace_filtops;
		break;
	default:
		return (EINVAL);
	}

	kn->kn_hook = sc;
	klist_insert(klist, kn);

	return (0);
}

static struct lltrace_cpu *
lltrace_next(struct lltrace_cpu *llt)
{
	struct lltrace_softc *sc = lltrace_sc;
	struct cpu_info *ci = curcpu();
	struct lltrace_cpu *nllt;
	unsigned int slot, oslot, nslot;

	/* check if we were preempted */
	nllt = ci->ci_schedstate.spc_lltrace;
	if (nllt != llt) {
		/* something preempted us and swapped buffers already */
		return (nllt);
	}

	slot = sc->sc_free;
	for (;;) {
		nslot = slot + 1;
		if (nslot > sc->sc_nbuffers) {
			if (sc->sc_mode == LLTRACE_MODE_HEAD)
				return (NULL);
		}

		oslot = atomic_cas_uint(&sc->sc_free, slot, nslot);
		if (slot == oslot)
			break;

		slot = oslot;
	}

	slot %= sc->sc_nbuffers;
	nllt = sc->sc_ring[slot];
	sc->sc_ring[slot] = NULL;

	slot = sc->sc_used;
	for (;;) {
		nslot = slot + 1;

		oslot = atomic_cas_uint(&sc->sc_used, slot, nslot);
		if (slot == oslot)
			break;

		slot = oslot;
	}

	lltrace_cpu_init(nllt, sc, ci, llt->llt_pid, llt->llt_tid,
	    llt->llt_wakeid);
	lltrace_cpu_fini(llt, sc);

	slot %= sc->sc_nbuffers;
	sc->sc_ring[slot] = llt;

	ci->ci_schedstate.spc_lltrace = nllt;

	return (nllt);
}

static struct lltrace_cpu *
lltrace_insert_record(struct lltrace_cpu *llt, uint64_t type, uint64_t record,
    const uint64_t *extra, unsigned int n)
{
	unsigned int slot, oslot, nslot;
	uint64_t *slots;

	record |= type << LLTRACE_TYPE_SHIFT;
	record |= n++ << LLTRACE_LEN_SHIFT;

	slot = llt->llt_slot;
	for (;;) {
		nslot = slot + n;
		if (nslot > nitems(llt->llt_buffer.llt_slots)) {
			unsigned long s;

			s = intr_disable();
			llt = lltrace_next(llt);
			intr_restore(s);

			if (llt == NULL)
				return (NULL);

			slot = llt->llt_slot;
			continue;
		}

		oslot = lltrace_cas(&llt->llt_slot, slot, nslot);
		if (slot == oslot)
			break;

		slot = oslot;
	}

	slots = llt->llt_buffer.llt_slots + slot;
	*slots = record;
	while (n > 1) {
		*(++slots) = *(extra++);
		n--;
	}

	return (llt);
}

static struct lltrace_cpu *
lltrace_insert(struct lltrace_cpu *llt, uint64_t type, uint64_t record,
    const uint64_t *extra, unsigned int n)
{
	record |= lltrace_ts();
	return (lltrace_insert_record(llt, type, record, extra, n));
}

void
lltrace_statclock(struct lltrace_cpu *llt, int usermode, unsigned long pc)
{
#if 0
	uint64_t event = usermode ? LLTRACE_EVENT_PC_U : LLTRACE_EVENT_PC_K;
	uint64_t extra[1] = { pc };

	lltrace_insert(llt, (event | nitems(extra)) << LLTRACE_EVENT_SHIFT,
	    extra, nitems(extra));
#endif
}

void
lltrace_syscall(struct lltrace_cpu *llt, register_t code,
    size_t argsize, const register_t *args)
{
	uint64_t record = LLTRACE_EVENT_PHASE_START <<
	    LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_SYSCALL <<
	    LLTRACE_EVENT_CLASS_SHIFT;
	record |= ((uint64_t)code & LLTRACE_SYSCALL_MASK) <<
	    LLTRACE_SYSCALL_SHIFT;

	if (argsize > 0)
		record |= (uint64_t)args[0] << LLTRACE_SYSCALL_V_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
}

void
lltrace_sysret(struct lltrace_cpu *llt, register_t code,
    int error, const register_t retvals[2])
{
	uint64_t record;

	record = LLTRACE_EVENT_PHASE_END <<
	    LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_SYSCALL <<
	    LLTRACE_EVENT_CLASS_SHIFT;
	record |= ((uint64_t)code & LLTRACE_SYSCALL_MASK) <<
	    LLTRACE_SYSCALL_SHIFT;
	record |= (uint64_t)error << LLTRACE_SYSCALL_V_SHIFT;

	llt = lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
	if (llt == NULL) {
		struct lltrace_softc *sc = lltrace_sc;

		rw_enter_write(&sc->sc_lock);
		if (sc->sc_running)
			lltrace_stop(sc, curproc);

		knote_locked(&sc->sc_sel.si_note, 0);
		if (sc->sc_reading)
			wakeup(&sc->sc_reading);
		rw_exit_write(&sc->sc_lock);
	}
}

struct lltrace_cpu *
lltrace_pidname(struct lltrace_cpu *llt, struct proc *p)
{
	struct process *ps = p->p_p;
	uint64_t record;
	uint64_t extra[3];
	unsigned int l, n;

	CTASSERT(sizeof(extra) == sizeof(ps->ps_comm));

	record = LLTRACE_ID_TYPE_TID << LLTRACE_ID_TYPE_SHIFT;
	record |= (uint64_t)p->p_tid << LLTRACE_ID_TID_SHIFT;
	record |= (uint64_t)ps->ps_pid << LLTRACE_ID_TID_PID_SHIFT;
	if (ISSET(ps->ps_flags, PS_SYSTEM))
		record |= LLTRACE_ID_TID_SYSTEM;

	extra[0] = extra[1] = extra[2] = 0; /* memset */
	l = strlcpy((char *)extra, p->p_p->ps_comm, sizeof(extra));

	/* turn the string length into the number of slots we need */
	n = howmany(l, sizeof(uint64_t));

	return (lltrace_insert_record(llt, LLTRACE_TYPE_ID, record, extra, n));
}

void
lltrace_switch(struct lltrace_cpu *llt, struct proc *op, struct proc *np)
{
	struct process *nps = np->p_p;
	uint64_t state;
	uint64_t record;
	unsigned int pid;
	unsigned int wake;

	llt = lltrace_pidname(llt, np);
	if (llt == NULL)
		return;

	record = LLTRACE_EVENT_PHASE_INSTANT <<
	    LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_SCHED <<
	    LLTRACE_EVENT_CLASS_SHIFT;
	record |= (uint64_t)np->p_tid << LLTRACE_EVENT_DATA_SHIFT;

	/* record what we think the state of the outgoing thread is */
	if (op == NULL)
		state = LLTRACE_SCHED_STATE_DEAD;
	else if (ISSET(op->p_flag, P_WEXIT))
		state = LLTRACE_SCHED_STATE_DYING;
	else if (op->p_wchan != 0)
		state = LLTRACE_SCHED_STATE_SUSPENDED;
	else
		state = LLTRACE_SCHED_STATE_BLOCKED;

	record |= (state << LLTRACE_SCHED_STATE_SHIFT);

	pid = nps->ps_pid;
	if (ISSET(nps->ps_flags, PS_SYSTEM))
		pid |= (1U << 31);

	llt->llt_pid = pid;
	llt->llt_tid = np->p_tid;

	wake = np->p_wakeid != 0;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, &np->p_wakeid, wake);

	if (wake)
		np->p_wakeid = 0;
}

void
lltrace_runnable(struct lltrace_cpu *llt, struct proc *p)
{
	uint64_t record;
	uint64_t wakeid;

	llt = lltrace_pidname(llt, p);
	if (llt == NULL)
		return;

	record = LLTRACE_EVENT_PHASE_INSTANT <<
	    LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_WAKE <<
	    LLTRACE_EVENT_CLASS_SHIFT;
	record |= (uint64_t)p->p_tid << LLTRACE_EVENT_DATA_SHIFT;

	wakeid = (uint64_t)cpu_number() << 48;
	wakeid |= (llt->llt_wakeid += 2) & LLTRACE_MASK(48);
	p->p_wakeid = wakeid;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, &p->p_wakeid, 1);
}

void
lltrace_sched_enter(struct lltrace_cpu *llt)
{
	uint64_t record = LLTRACE_EVENT_PHASE_START <<
	    LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_SCHED <<
	    LLTRACE_EVENT_CLASS_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
}

void
lltrace_sched_leave(struct lltrace_cpu *llt)
{
	uint64_t record = LLTRACE_EVENT_PHASE_END <<
	    LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_SCHED <<
	    LLTRACE_EVENT_CLASS_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
}

void
lltrace_idle(struct lltrace_cpu *llt, unsigned int idle)
{
	uint64_t record =
	    (idle ? LLTRACE_EVENT_PHASE_START : LLTRACE_EVENT_PHASE_END) <<
	    LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_IDLE << LLTRACE_EVENT_CLASS_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
}

void
lltrace_event_start(struct lltrace_cpu *llt, unsigned int class)
{
	uint64_t record = LLTRACE_EVENT_PHASE_START <<
	    LLTRACE_EVENT_PHASE_SHIFT;
	record |= class << LLTRACE_EVENT_CLASS_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
}

void
lltrace_event_end(struct lltrace_cpu *llt, unsigned int class)
{
	uint64_t record = LLTRACE_EVENT_PHASE_END <<
	    LLTRACE_EVENT_PHASE_SHIFT;
	record |= class << LLTRACE_EVENT_CLASS_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
}

static inline void
lltrace_intr(struct lltrace_cpu *llt, uint64_t phase,
    uint64_t type, uint64_t data)
{
	uint64_t record = phase << LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_INTR << LLTRACE_EVENT_CLASS_SHIFT;
	record |= type << LLTRACE_INTR_T_SHIFT;
	record |= data << LLTRACE_INTR_DATA_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
}

void
lltrace_ipi(struct lltrace_cpu *llt, unsigned int cpu)
{
	lltrace_intr(llt, LLTRACE_EVENT_PHASE_INSTANT,
	    LLTRACE_INTR_T_IPI, cpu);
}

void
lltrace_intr_enter(struct lltrace_cpu *llt, unsigned int type, unsigned int vec)
{
	lltrace_intr(llt, LLTRACE_EVENT_PHASE_START, type, vec);
}

void
lltrace_intr_leave(struct lltrace_cpu *llt, unsigned int type, unsigned int vec)
{
	lltrace_intr(llt, LLTRACE_EVENT_PHASE_END, type, vec);
}

void
lltrace_lock(struct lltrace_cpu *llt, void *lock,
    unsigned int type, unsigned int step, unsigned long pc)
{
	uint64_t extra[1] = { pc };

	uint64_t record = (uint64_t)type << LLTRACE_LK_TYPE_SHIFT;
	record |= (uint64_t)step << LLTRACE_LK_PHASE_SHIFT;
	record |= (uint64_t)lock << LLTRACE_LK_ADDR_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_LOCKING, record, extra, nitems(extra));
}

void
lltrace_count(struct lltrace_cpu *llt, unsigned int t, unsigned int v)
{
	uint64_t record;

	record = LLTRACE_EVENT_PHASE_INSTANT << LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_COUNT << LLTRACE_EVENT_CLASS_SHIFT;
	record |= (uint64_t)t << LLTRACE_COUNT_T_SHIFT;
	record |= (uint64_t)v << LLTRACE_COUNT_V_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
}

void
lltrace_mark(struct lltrace_cpu *llt)
{
#if 0
	uint64_t record = LLTRACE_EVENT_MARK << LLTRACE_EVENT_SHIFT;

	lltrace_insert(llt, record, NULL, 0);
#endif
}

static void
lltrace_fn(struct lltrace_cpu *llt, unsigned int phase, void *fn)
{
	uint64_t record = (uint64_t)phase << LLTRACE_EVENT_PHASE_SHIFT;
	record |= LLTRACE_EVENT_CLASS_FUNC << LLTRACE_EVENT_CLASS_SHIFT;
	/* 32 bits is enough to identify most symbols */
	record |= (uint64_t)fn << LLTRACE_EVENT_DATA_SHIFT;

	lltrace_insert(llt, LLTRACE_TYPE_EVENT, record, NULL, 0);
}

void
lltrace_fn_enter(struct lltrace_cpu *llt, void *fn)
{
	lltrace_fn(llt, LLTRACE_EVENT_PHASE_START, fn);
}

void
lltrace_fn_leave(struct lltrace_cpu *llt, void *fn)
{
	lltrace_fn(llt, LLTRACE_EVENT_PHASE_END, fn);
}

void
__cyg_profile_func_enter(void *fn, void *pc)
{
	struct lltrace_cpu *llt;

	llt = lltrace_enter();
	if (llt == NULL)
		return;

	lltrace_fn_enter(llt, fn);
}

void
__cyg_profile_func_exit(void *fn, void *pc)
{
	struct lltrace_cpu *llt;

	llt = lltrace_enter();
	if (llt == NULL)
		return;

	lltrace_fn_leave(llt, fn);
}
