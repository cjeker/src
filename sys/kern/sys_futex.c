/*	$OpenBSD: sys_futex.c,v 1.22 2023/08/14 07:42:34 miod Exp $ */

/*
 * Copyright (c) 2016-2017 Martin Pieuchot
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/syscallargs.h>
#include <sys/pool.h>
#include <sys/time.h>
#include <sys/rwlock.h>
#include <sys/kernel.h> /* tick_nsec */
#include <sys/futex.h>

#ifdef KTRACE
#include <sys/ktrace.h>
#endif

#include <uvm/uvm.h>

/*
 * Kernel representation of a futex.
 */
struct futex {
	TAILQ_ENTRY(futex)	 ft_entry;	/* list of all futexes */
	struct process		*ft_ps;
	struct uvm_object	*ft_obj;	/* UVM object */
	struct vm_amap		*ft_amap;	/* UVM amap */
	volatile voff_t		 ft_off;	/* UVM offset */

	struct proc * volatile	 ft_proc;
};

static int
futex_is_eq(const struct futex *a, const struct futex *b)
{
	return (a->ft_off == b->ft_off &&
	    a->ft_ps == b->ft_ps &&
	    a->ft_obj == b->ft_obj &&
	    a->ft_amap == b->ft_amap);
}

TAILQ_HEAD(futexen, futex);

struct futex_bucket {
	struct futexen		fb_list;
	struct rwlock		fb_lock;
	uint32_t		fb_id;		/* for lock ordering */
} __aligned(64);

/* Syscall helpers. */
static int	futex_wait(struct proc *, uint32_t *, uint32_t,
		    const struct timespec *, int);
static int	futex_wake(struct proc *, uint32_t *, uint32_t, int,
		    register_t *);
static int	futex_requeue(struct proc *, uint32_t *, uint32_t,
		    uint32_t *, uint32_t, int, register_t *);

/* Flags for futex_get(). kernel private flags sit in FUTEX_OP_MASK space */
#define FT_PRIVATE	FUTEX_PRIVATE_FLAG	/* Futex is process-private. */

#define FUTEX_BUCKET_BITS	6
#define FUTEX_BUCKET_SIZE	(1U << FUTEX_BUCKET_BITS)
#define FUTEX_BUCKET_MASK	(FUTEX_BUCKET_SIZE - 1)

static struct futex_bucket futex_hash[FUTEX_BUCKET_SIZE];

void
futex_init(void)
{
	struct futex_bucket *fb;
	unsigned int i;

	for (i = 0; i < nitems(futex_hash); i++) {
		fb = &futex_hash[i];

		TAILQ_INIT(&fb->fb_list);
		rw_init(&fb->fb_lock, "futexlk");

		fb->fb_id = arc4random();
		fb->fb_id &= ~FUTEX_BUCKET_MASK;
		fb->fb_id |= i;
	}
}

int
sys_futex(struct proc *p, void *v, register_t *retval)
{
	struct sys_futex_args /* {
		syscallarg(uint32_t *) f;
		syscallarg(int) op;
		syscallarg(inr) val;
		syscallarg(const struct timespec *) timeout;
		syscallarg(uint32_t *) g;
	} */ *uap = v;
	uint32_t *uaddr = SCARG(uap, f);
	int op = SCARG(uap, op);
	uint32_t val = SCARG(uap, val);
	const struct timespec *timeout = SCARG(uap, timeout);
	void *g = SCARG(uap, g);
	int flags = op & FUTEX_FLAG_MASK;
	int error = 0;

	switch (op & FUTEX_OP_MASK) {
	case FUTEX_WAIT:
		error = futex_wait(p, uaddr, val, timeout, flags);
		break;
	case FUTEX_WAKE:
		error = futex_wake(p, uaddr, val, flags, retval);
		break;
	case FUTEX_REQUEUE:
		error = futex_requeue(p, uaddr, val, g,
		    (u_long)timeout, flags, retval);
		break;
	default:
		error = ENOSYS;
		break;
	}

	return error;
}

static void
futex_addrs(struct proc *p, struct futex *f, uint32_t *uaddr, int flags)
{
	vm_map_t map = &p->p_vmspace->vm_map;
	vm_map_entry_t entry;
	struct uvm_object *obj = NULL;
	struct vm_amap *amap = NULL;
	voff_t off = (vaddr_t)uaddr;
	struct process *ps;

	if (ISSET(flags, FT_PRIVATE))
		ps = p->p_p;
	else {
		ps = NULL;

		vm_map_lock_read(map);
		if (uvm_map_lookup_entry(map, (vaddr_t)uaddr, &entry) &&
		    entry->inheritance == MAP_INHERIT_SHARE) {
			if (UVM_ET_ISOBJ(entry)) {
				obj = entry->object.uvm_obj;
				off = entry->offset +
				    ((vaddr_t)uaddr - entry->start);
			} else if (entry->aref.ar_amap) {
				amap = entry->aref.ar_amap;
				off = ptoa(entry->aref.ar_pageoff) +
				    ((vaddr_t)uaddr - entry->start);
			}
		}
		vm_map_unlock_read(map);
	}

	f->ft_ps = ps;
	f->ft_obj = obj;
	f->ft_amap = amap;
	f->ft_off = off;
}

static inline struct futex_bucket *
futex_get_bucket(struct futex *f)
{
	uint32_t key = f->ft_off >> 3; /* watevs */
	key ^= key >> FUTEX_BUCKET_BITS;

	return (&futex_hash[key & FUTEX_BUCKET_MASK]);
}

static int
futex_remove(struct futex_bucket *ofb, struct futex *f)
{
	struct futex_bucket *fb;
	int rv;

	/*
	 * REQUEUE can move a futex between buckets, so follow it if needed.
	 */

	for (;;) {
		rw_enter_write(&ofb->fb_lock);
		fb = futex_get_bucket(f);
		if (ofb == fb)
			break;

		rw_exit_write(&ofb->fb_lock);
		ofb = fb;
	}

	rv = f->ft_proc != NULL;
	if (rv)
		TAILQ_REMOVE(&fb->fb_list, f, ft_entry);
	rw_exit_write(&fb->fb_lock);

	return (rv);
}

/*
 * Put the current thread on the sleep queue of the futex at address
 * ``uaddr''.  Let it sleep for the specified ``timeout'' time, or
 * indefinitely if the argument is NULL.
 */
static int
futex_wait(struct proc *p, uint32_t *uaddr, uint32_t val,
    const struct timespec *timeout, int flags)
{
	struct futex f;
	struct futex_bucket *fb;
	uint64_t to_ticks = 0;
	uint32_t cval;
	int error;

	if (timeout != NULL) {
		struct timespec ts;
		uint64_t nsecs;

		if ((error = copyin(timeout, &ts, sizeof(ts))))
			return error;
#ifdef KTRACE
		if (KTRPOINT(p, KTR_STRUCT))
			ktrreltimespec(p, &ts);
#endif
		if (ts.tv_sec < 0 || !timespecisvalid(&ts))
			return EINVAL;

		nsecs = MAX(1, MIN(TIMESPEC_TO_NSEC(&ts), MAXTSLP));
		to_ticks = (nsecs + tick_nsec - 1) / (tick_nsec + 1) + 1;
		if (to_ticks > INT_MAX)
			to_ticks = INT_MAX;
	}

	futex_addrs(p, &f, uaddr, flags);
	fb = futex_get_bucket(&f);

	f.ft_proc = p;
	rw_enter_write(&fb->fb_lock);
	TAILQ_INSERT_TAIL(&fb->fb_list, &f, ft_entry);
	rw_exit_write(&fb->fb_lock);

	/*
	 * Read user space futex value
	 */
	if ((error = copyin32(uaddr, &cval)) != 0)
		goto exit;

	/* If the value changed, stop here. */
	if (cval != val) {
		error = EAGAIN;
		goto exit;
	}

	sleep_setup(&f, PWAIT|PCATCH, "fsleep");
	error = sleep_finish(to_ticks, f.ft_proc != NULL);
	/* Remove ourself if we haven't been awaken. */
	if (error != 0 || f.ft_proc != NULL) {
		if (futex_remove(fb, &f) == 0)
			error = 0;

		switch (error) {
		case ERESTART:
			error = ECANCELED;
			break;
		case EWOULDBLOCK:
			error = ETIMEDOUT;
			break;
		}
	}

	return error;
exit:
	if (f.ft_proc != NULL)
		futex_remove(fb, &f);
	return error;
}

static void
futexen_wakeup(struct futexen *fl)
{
	struct futex *f, *nf;
	struct proc *p;

	/*
	 * take care to avoid referencing f after we set ft_proc
	 * to NULL (and wake the associated thread up). f is on the
	 * stack of the thread we're trying let out of the kernel,
	 * so it can go away.
	 */

	SCHED_LOCK();
	TAILQ_FOREACH_SAFE(f, fl, ft_entry, nf) {
		p = f->ft_proc;
		f->ft_proc = NULL;
		wakeup_proc(p, 0);
	}
	SCHED_UNLOCK();
}

/*
 * Wakeup at most ``n'' sibling threads sleeping on a futex at address
 * ``uaddr'' and requeue at most ``m'' sibling threads on a futex at
 * address ``uaddr2''.
 */
static int
futex_requeue(struct proc *p, uint32_t *uaddr, uint32_t n,
    uint32_t *uaddr2, uint32_t m, int flags, register_t *retval)
{
	struct futexen fl = TAILQ_HEAD_INITIALIZER(fl);
	struct futex okey, nkey;
	struct futex *f, *nf, *mf = NULL;
	struct futex_bucket *ofb, *nfb;
	uint32_t count = 0;

	if (m == 0)
		return futex_wake(p, uaddr, n, flags, retval);

	futex_addrs(p, &okey, uaddr, flags);
	ofb = futex_get_bucket(&okey);
	futex_addrs(p, &nkey, uaddr2, flags);
	nfb = futex_get_bucket(&nkey);

	if (ofb->fb_id < nfb->fb_id) {
		rw_enter_write(&ofb->fb_lock);
		rw_enter_write(&nfb->fb_lock);
	} else if (ofb->fb_id > nfb->fb_id) {
		rw_enter_write(&nfb->fb_lock);
		rw_enter_write(&ofb->fb_lock);
	} else
		rw_enter_write(&ofb->fb_lock);

	TAILQ_FOREACH_SAFE(f, &ofb->fb_list, ft_entry, nf) {
		/* __builtin_prefetch(nf, 1); */
		KASSERT(f->ft_proc != NULL);

		if (!futex_is_eq(f, &okey))
			continue;

		TAILQ_REMOVE(&ofb->fb_list, f, ft_entry);
		TAILQ_INSERT_TAIL(&fl, f, ft_entry);

		if (++count == n) {
			mf = nf;
			break;
		}
	}

	if (!TAILQ_EMPTY(&fl))
		futexen_wakeup(&fl);

	/* update matching futexes */
	if (mf != NULL) {
		/*
		 * only iterate from the current entry to the tail
		 * of the list as it is now in case we're requeueing
		 * on the end of the same list.
		 */
		nf = TAILQ_LAST(&ofb->fb_list, futexen);
		do {
			f = mf;
			mf = TAILQ_NEXT(f, ft_entry);
			/* __builtin_prefetch(mf, 1); */

			KASSERT(f->ft_proc != NULL);

			if (!futex_is_eq(f, &okey))
				continue;

			TAILQ_REMOVE(&ofb->fb_list, f, ft_entry);
			/* it should only be ft_off that changes, but eh */
			f->ft_ps = nkey.ft_ps;
			f->ft_obj = nkey.ft_obj;
			f->ft_amap = nkey.ft_amap;
			f->ft_off = nkey.ft_off;

			TAILQ_INSERT_TAIL(&nfb->fb_list, f, ft_entry);

			if (--m == 0)
				break;
		} while (f != nf);
	}

	if (ofb->fb_id != nfb->fb_id)
		rw_exit_write(&nfb->fb_lock);
	rw_exit_write(&ofb->fb_lock);

	*retval = count;
	return 0;
}

/*
 * Wakeup at most ``n'' sibling threads sleeping on a futex at address
 * ``uaddr''.
 */
static int
futex_wake(struct proc *p, uint32_t *uaddr, uint32_t n, int flags,
    register_t *retval)
{
	struct futexen fl = TAILQ_HEAD_INITIALIZER(fl);
	struct futex key;
	struct futex *f, *nf;
	struct futex_bucket *fb;
	int count = 0;

	if (n == 0) {
		*retval = 0;
		return 0;
	}

	futex_addrs(p, &key, uaddr, flags);
	fb = futex_get_bucket(&key);

	rw_enter_write(&fb->fb_lock);

	TAILQ_FOREACH_SAFE(f, &fb->fb_list, ft_entry, nf) {
		/* __builtin_prefetch(nf, 1); */
		KASSERT(f->ft_proc != NULL);

		if (!futex_is_eq(f, &key))
			continue;

		TAILQ_REMOVE(&fb->fb_list, f, ft_entry);
		TAILQ_INSERT_TAIL(&fl, f, ft_entry);

		if (++count == n)
			break;
	}

	if (!TAILQ_EMPTY(&fl))
		futexen_wakeup(&fl);

	rw_exit_write(&fb->fb_lock);

	*retval = count;
	return 0;
}
