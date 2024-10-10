/*	$OpenBSD: kern_rwlock.c,v 1.50 2023/07/14 07:07:08 claudio Exp $	*/

/*
 * Copyright (c) 2002, 2003 Artur Grabowski <art@openbsd.org>
 * Copyright (c) 2011 Thordur Bjornsson <thib@secnorth.net>
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
#include <sys/pool.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/limits.h>
#include <sys/atomic.h>
#include <sys/witness.h>
#include <sys/tracepoint.h>

struct rwlock_waiter {
	volatile unsigned int	  rww_wait;
	struct proc		 *rww_owner;
	struct rwlock_waiter	**rww_prev;
	struct rwlock_waiter	 *rww_next;
};

static int rw_write(struct rwlock *, int);
static int rw_read(struct rwlock *, int);
static int rw_downgrade(struct rwlock *, int);

/*
 * Other OSes implement more sophisticated mechanism to determine how long the
 * process attempting to acquire the lock should be spinning. We start with
 * the most simple approach: we do RW_SPINS attempts at most before eventually
 * giving up and putting the process to sleep queue.
 */
#define RW_SPINS	1000

static void
_rw_init_flags_witness(struct rwlock *rwl, const char *name, int lo_flags,
    const struct lock_type *type)
{
	rwl->rwl_lock = 0;
	rwl->rwl_state = 0;
	rwl->rwl_readers = 0;
	rwl->rwl_depth = 0;
	rwl->rwl_owner = NULL;
	rwl->rwl_name = name;
	rwl->rwl_head = NULL;
	rwl->rwl_tail = &rwl->rwl_head;

#ifdef WITNESS
	rwl->rwl_lock_obj.lo_flags = lo_flags;
	rwl->rwl_lock_obj.lo_name = name;
	rwl->rwl_lock_obj.lo_type = type;
	WITNESS_INIT(&rwl->rwl_lock_obj, type);
#else
	(void)type;
	(void)lo_flags;
#endif
}

void
_rw_init_flags(struct rwlock *rwl, const char *name, int flags,
    const struct lock_type *type)
{
	_rw_init_flags_witness(rwl, name, RWLOCK_LO_FLAGS(flags), type);
}

#ifdef MULTIPROCESSOR
static inline void
rw_lock_enter(struct rwlock *rwl)
{
	while (atomic_cas_uint(&rwl->rwl_lock, 0, 1) != 0) {
		do {
			CPU_BUSY_CYCLE();
		} while (atomic_load_int(&rwl->rwl_lock) != 0);
	}
	membar_enter_after_atomic();
}

static inline void
rw_lock_leave(struct rwlock *rwl)
{
	atomic_store_int(&rwl->rwl_lock, 0);
}
#else /* MULTIPROCESSOR */
static inline void
rw_lock_enter(struct rwlock *rwl)
{
	rwl->rwl_lock = 1;
}

static inline void
rw_lock_leave(struct rwlock *rwl)
{
	rwl->rwl_lock = 0;
}
#endif /* MULTIPROCESSOR */

static inline void
rw_insert(struct rwlock *rwl, struct rwlock_waiter *rww)
{
	struct rwlock_waiter **tail = rwl->rwl_tail;

	if (__predict_false(tail == NULL))
		tail = &rwl->rwl_head;

	rww->rww_next = NULL;
	rww->rww_prev = tail;

	*tail = rww;
	rwl->rwl_tail = &rww->rww_next;
}

static inline struct rwlock_waiter *
rw_first(struct rwlock *rwl)
{
	return (rwl->rwl_head);
}

static inline void
rw_remove(struct rwlock *rwl, struct rwlock_waiter *rww)
{
	if (rww->rww_next != NULL)
		rww->rww_next->rww_prev = rww->rww_prev;
	else
		rwl->rwl_tail = rww->rww_prev;
	*rww->rww_prev = rww->rww_next;
}

static int
rw_write(struct rwlock *rwl, int flags)
{
	struct proc *self = curproc;
	unsigned int state;
	struct rwlock_waiter waiter = { .rww_wait = 1, .rww_owner = self };
	int prio = PLOCK - 4;

	/* Avoid deadlocks after panic or in DDB */
	if (panicstr || db_active)
		return (0);

#ifdef WITNESS
	if (!ISSET(flags, RW_NOSLEEP)) {
		int lop_flags = LOP_NEWORDER | LOP_EXCLUSIVE;
		if (ISSET(flags, RW_DUPOK))
			lop_flags |= LOP_DUPOK;
		WITNESS_CHECKORDER(&rwl->rwl_lock_obj, lop_flags, NULL);
	}
#endif

	rw_lock_enter(rwl);
	state = rwl->rwl_state;
	if (state == 0) {
		KASSERT(rwl->rwl_owner == NULL);
		KASSERT(rwl->rwl_depth == 0);
		rwl->rwl_state = RW_WRITE;
		rwl->rwl_owner = self;
		rwl->rwl_depth = 1;
	} else {
		if (rwl->rwl_owner == self) {
			KASSERT(state == RW_WRITE);
			rw_lock_leave(rwl);
			/* for rrwlocks to handle */
			return (EDEADLK);
		}
		if (ISSET(flags, RW_NOSLEEP)) {
			rw_lock_leave(rwl);
			return (EBUSY);
		}
		rw_insert(rwl, &waiter);
	}
	rw_lock_leave(rwl);

	if (state == 0) {
		membar_enter_after_atomic();
		WITNESS_LOCK(&rwl->rwl_lock_obj, LOP_EXCLUSIVE);
		LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW, LLTRACE_LK_I_EXCL,
		    (unsigned long)__builtin_return_address(0));
		return (0);
	}

	LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW, LLTRACE_LK_A_START,
	    (unsigned long)__builtin_return_address(0));

#ifdef MULTIPROCESSOR
	if (!_kernel_lock_held()) {
		unsigned int i;

		for (i = 0; i < RW_SPINS; i++) {
			CPU_BUSY_CYCLE();
			if (!atomic_load_int(&waiter.rww_wait))
				goto locked;
		}
	}
#endif

	if (ISSET(flags, RW_INTR))
		prio |= PCATCH;

	do {
		int error;

		sleep_setup(&waiter, prio, rwl->rwl_name);
		error = sleep_finish(0, atomic_load_int(&waiter.rww_wait));
		if (ISSET(flags, RW_INTR) && (error != 0)) {
			rw_lock_enter(rwl);
			if (waiter.rww_wait)
				rw_remove(rwl, &waiter);
			else {
				KASSERT(rwl->rwl_state == RW_WRITE);
				KASSERT(rwl->rwl_owner == self);
				error = 0;
			}
			rw_lock_leave(rwl);
			if (error != 0) {
				LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW,
				    LLTRACE_LK_A_ABORT,
				    (unsigned long)__builtin_return_address(0));
				return (error);
			}

			goto locked;
		}
	} while (atomic_load_int(&waiter.rww_wait));

locked:
	WITNESS_LOCK(&rwl->rwl_lock_obj, LOP_EXCLUSIVE);
	LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW, LLTRACE_LK_A_EXCL,
	    (unsigned long)__builtin_return_address(0));
	if (ISSET(flags, RW_SLEEPFAIL)) {
		rw_exit(rwl);
		return (EAGAIN);
	}

	__builtin_prefetch(rwl, 1);
	membar_enter();
	return (0);
}

void
rw_enter_write(struct rwlock *rwl)
{
	int error;

	error = rw_write(rwl, 0);
	if (error == EDEADLK)
		panic("%s(%p): %s deadlock", __func__, rwl, rwl->rwl_name);
}

void
rw_exit_write(struct rwlock *rwl)
{
	rw_exit(rwl);
}

static int
rw_read(struct rwlock *rwl, int flags)
{
	struct proc *self = curproc;
	struct proc *owner = NULL;
	unsigned int state;
	int prio = PLOCK;

	/* Avoid deadlocks after panic or in DDB */
	if (panicstr || db_active)
		return (0);

#ifdef WITNESS
	if (!ISSET(flags, RW_NOSLEEP)) {
		int lop_flags = LOP_NEWORDER;
		if (ISSET(flags, RW_DUPOK))
			lop_flags |= LOP_DUPOK;
		WITNESS_CHECKORDER(&rwl->rwl_lock_obj, lop_flags, NULL);
	}
#endif

	rw_lock_enter(rwl);
	state = rwl->rwl_state;
	switch (state) {
	case 0:
		rwl->rwl_state = state = RW_READ;
		break;
	case RW_WRITE:
		owner = rwl->rwl_owner;
		KASSERT(owner != NULL);
		KASSERT(owner != self);
		if (ISSET(flags, RW_NOSLEEP)) {
			rw_lock_leave(rwl);
			return (EBUSY);
		}
		break;
	}
	rwl->rwl_readers++;
	rw_lock_leave(rwl);

	if (state == RW_READ) {
		WITNESS_LOCK(&rwl->rwl_lock_obj, 0);
		LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW, LLTRACE_LK_I_SHARED,
		    (unsigned long)__builtin_return_address(0));
		membar_enter_after_atomic();
		return (0);
	}

	LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW, LLTRACE_LK_A_START,
	    (unsigned long)__builtin_return_address(0));

#ifdef MULTIPROCESSOR
	if (!_kernel_lock_held()) {
		unsigned int i;

		for (i = 0; i < RW_SPINS; i++) {
			CPU_BUSY_CYCLE();
			state = atomic_load_int(&rwl->rwl_state);
			if (state == RW_READ)
				goto locked;
		}
#endif
	}

	if (ISSET(flags, RW_INTR))
		prio |= PCATCH;

	do {
		int error;

		sleep_setup(&rwl->rwl_readers, prio, rwl->rwl_name);
		state = atomic_load_int(&rwl->rwl_state);
		error = sleep_finish(0, state != RW_READ);
		if (ISSET(flags, RW_INTR) && (error != 0)) {
			rw_lock_enter(rwl);
			if (rwl->rwl_state != RW_READ) {
				KASSERT(rwl->rwl_readers > 0);
				rwl->rwl_readers--;
			} else
				error = 0;
			rw_lock_leave(rwl);
			if (error != 0) {
				LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW,
				    LLTRACE_LK_A_ABORT,
				    (unsigned long)__builtin_return_address(0));
				return (error);
			}
			goto locked;
		}
		state = atomic_load_int(&rwl->rwl_state);
	} while (state != RW_READ);

locked:
	WITNESS_LOCK(&rwl->rwl_lock_obj, 0);
	LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW, LLTRACE_LK_A_SHARED,
	    (unsigned long)__builtin_return_address(0));
	if (ISSET(flags, RW_SLEEPFAIL)) {
		rw_exit(rwl);
		return (EAGAIN);
	}

	membar_enter();
	return (0);
}

void
rw_enter_read(struct rwlock *rwl)
{
	rw_read(rwl, 0);
}

void
rw_exit_read(struct rwlock *rwl)
{
	rw_exit(rwl);
}

static int
rw_downgrade(struct rwlock *rwl, int flags)
{
	struct proc *self = curproc;
	int nwake;

	/* Avoid deadlocks after panic or in DDB */
	if (panicstr || db_active)
		return (0);

	rw_lock_enter(rwl);
	KASSERT(rwl->rwl_state == RW_WRITE);
	KASSERT(rwl->rwl_owner == self);
	KASSERT(rwl->rwl_depth == 1);
	nwake = rwl->rwl_readers++;
	rwl->rwl_owner = NULL;
	rwl->rwl_state = RW_READ;
	rw_lock_leave(rwl);

	LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW, LLTRACE_LK_DOWNGRADE,
	    (unsigned long)__builtin_return_address(0));
	WITNESS_DOWNGRADE(&rwl->rwl_lock_obj, 0);

	if (nwake > 0)
		wakeup(&rwl->rwl_readers);

	return (0);
}

int
rw_enter(struct rwlock *rwl, int flags)
{
	int op = flags & RW_OPMASK;
	int error;

	switch (op) {
	case RW_WRITE:
		error = rw_write(rwl, flags);
		if (error == EDEADLK) {
			panic("%s(%p): %s deadlock", __func__, rwl,
			    rwl->rwl_name);
		}
		break;
	case RW_READ:
		error = rw_read(rwl, flags);
		break;
	case RW_DOWNGRADE:
		error = rw_downgrade(rwl, flags);
		break;
	default:
		panic("%s(%p, 0x%x): unknown op 0x%x", __func__, rwl, flags,
		    op);
		/* NOTREACHED */
	}

	return (error);
}

void
rw_exit(struct rwlock *rwl)
{
	struct proc *self = curproc;
	struct rwlock_waiter *rww;
	void *wchan = NULL;
	int wrlock = 0;

	/* Avoid deadlocks after panic or in DDB */
	if (panicstr || db_active)
		return;

	rw_lock_enter(rwl);
	switch (rwl->rwl_state) {
	case RW_WRITE:
		KASSERT(rwl->rwl_owner == self);
		wrlock = 1;
		if (--rwl->rwl_depth > 0)
			goto leave;
		LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW, LLTRACE_LK_R_EXCL,
		    (unsigned long)__builtin_return_address(0));
		break;
	case RW_READ:
		KASSERT(rwl->rwl_owner == NULL);
		if (--rwl->rwl_readers > 0)
			goto leave;
		LLTRACE(lltrace_lock, rwl, LLTRACE_LK_RW, LLTRACE_LK_R_SHARED,
		    (unsigned long)__builtin_return_address(0));
		break;
	default:
		panic("%s(%p): %s unexpected state %u", __func__, rwl,
		    rwl->rwl_name, rwl->rwl_state);
		/* NOTREACHED */
	}
	membar_exit();

	rww = rw_first(rwl);
	if (rww != NULL) {
		rw_remove(rwl, rww);

		/* move ownership */
		rwl->rwl_state = RW_WRITE;
		rwl->rwl_owner = rww->rww_owner;
		rwl->rwl_depth = 1;

		wchan = rww;

		atomic_store_int(&rww->rww_wait, 0);
	} else {
		rwl->rwl_owner = NULL;

		if (rwl->rwl_readers > 0) {
			wchan = &rwl->rwl_readers;
			rwl->rwl_state = RW_READ;
		} else
			rwl->rwl_state = 0;
	}
leave:
	rw_lock_leave(rwl);

	WITNESS_UNLOCK(&rwl->rwl_lock_obj, wrlock ? LOP_EXCLUSIVE : 0);
	(void)wrlock;

	if (__predict_false(wchan != NULL))
		wakeup(wchan);
}

int
rw_status(struct rwlock *rwl)
{
	struct proc *self = curproc;
	struct proc *owner;
	unsigned int state;

	rw_lock_enter(rwl);
	state = rwl->rwl_state;
	owner = rwl->rwl_owner;
	rw_lock_leave(rwl);

	if (state == RW_WRITE && owner != self)
		state = RW_WRITE_OTHER;

	return (state);
}

#ifdef DIAGNOSTIC
void
rw_assert_wrlock(struct rwlock *rwl)
{
	if (panicstr || db_active)
		return;

#ifdef WITNESS
	witness_assert(&rwl->rwl_lock_obj, LA_XLOCKED);
#else
	switch (rw_status(rwl)) {
	case RW_WRITE:
		break;
	case RW_WRITE_OTHER:
		panic("%s: lock not held by this process", rwl->rwl_name);
		/* NOTREACHED */
	default:
		panic("%s: lock not held", rwl->rwl_name);
		/* NOTREACHED */
	}
#endif
}

void
rw_assert_rdlock(struct rwlock *rwl)
{
	if (panicstr || db_active)
		return;

#ifdef WITNESS
	witness_assert(&rwl->rwl_lock_obj, LA_SLOCKED);
#else
	if (rw_status(rwl) != RW_READ)
		panic("%s: lock not shared", rwl->rwl_name);
#endif
}

void
rw_assert_anylock(struct rwlock *rwl)
{
	if (panicstr || db_active)
		return;

#ifdef WITNESS
	witness_assert(&rwl->rwl_lock_obj, LA_LOCKED);
#else
	switch (rw_status(rwl)) {
	case RW_WRITE_OTHER:
		panic("%s: lock held by different process", rwl->rwl_name);
	case 0:
		panic("%s: lock not held", rwl->rwl_name);
	}
#endif
}

void
rw_assert_unlocked(struct rwlock *rwl)
{
	if (panicstr || db_active)
		return;

#ifdef WITNESS
	witness_assert(&rwl->rwl_lock_obj, LA_UNLOCKED);
#else
	if (rw_status(rwl) == RW_WRITE)
		panic("%s: lock held", rwl->rwl_name);
#endif
}
#endif

/* recursive rwlocks; */
void
_rrw_init_flags(struct rrwlock *rrwl, const char *name, int flags,
    const struct lock_type *type)
{
	_rw_init_flags_witness(&rrwl->rrwl_lock, name, RRWLOCK_LO_FLAGS(flags),
	    type);
}

int
rrw_enter(struct rrwlock *rrwl, int flags)
{
	struct rwlock *rwl = &rrwl->rrwl_lock;
	int op = flags & RW_OPMASK;
	int error;

	switch (op) {
	case RW_WRITE:
		error = rw_write(rwl, flags);
		if (error == EDEADLK && !ISSET(flags, RW_RECURSEFAIL)) {
			WITNESS_LOCK(&rwl->rwl_lock_obj, LOP_EXCLUSIVE);
			rwl->rwl_depth++;
			error = 0;
		}
		break;
	case RW_READ:
		error = rw_read(rwl, flags);
		break;
	case RW_DOWNGRADE:
		panic("%s(%p, 0x%x): downgrade not supported", __func__,
		    rwl, flags);
		break;
	default:
		panic("%s(%p, 0x%x): unknown op 0x%x", __func__, rwl, flags,
		    op);
		/* NOTREACHED */
	}

	return (error);
}

void
rrw_exit(struct rrwlock *rrwl)
{
	struct rwlock *rwl = &rrwl->rrwl_lock;

	rw_exit(rwl);
}

int
rrw_status(struct rrwlock *rrwl)
{
	struct rwlock *rwl = &rrwl->rrwl_lock;

	return (rw_status(rwl));
}

/*-
 * Copyright (c) 2008 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Andrew Doran.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define	RWLOCK_OBJ_MAGIC	0x5aa3c85d
struct rwlock_obj {
	struct rwlock	ro_lock;
	u_int		ro_magic;
	u_int		ro_refcnt;
};


struct pool rwlock_obj_pool;

/*
 * rw_obj_init:
 *
 *	Initialize the mutex object store.
 */
void
rw_obj_init(void)
{
	pool_init(&rwlock_obj_pool, sizeof(struct rwlock_obj), 0, IPL_MPFLOOR,
	    PR_WAITOK, "rwobjpl", NULL);
}

/*
 * rw_obj_alloc:
 *
 *	Allocate a single lock object.
 */
void
_rw_obj_alloc_flags(struct rwlock **lock, const char *name, int flags,
    struct lock_type *type)
{
	struct rwlock_obj *mo;

	mo = pool_get(&rwlock_obj_pool, PR_WAITOK);
	mo->ro_magic = RWLOCK_OBJ_MAGIC;
	_rw_init_flags(&mo->ro_lock, name, flags, type);
	mo->ro_refcnt = 1;

	*lock = &mo->ro_lock;
}

/*
 * rw_obj_hold:
 *
 *	Add a single reference to a lock object.  A reference to the object
 *	must already be held, and must be held across this call.
 */

void
rw_obj_hold(struct rwlock *lock)
{
	struct rwlock_obj *mo = (struct rwlock_obj *)lock;

	KASSERTMSG(mo->ro_magic == RWLOCK_OBJ_MAGIC,
	    "%s: lock %p: mo->ro_magic (%#x) != RWLOCK_OBJ_MAGIC (%#x)",
	     __func__, mo, mo->ro_magic, RWLOCK_OBJ_MAGIC);
	KASSERTMSG(mo->ro_refcnt > 0,
	    "%s: lock %p: mo->ro_refcnt (%#x) == 0",
	     __func__, mo, mo->ro_refcnt);

	atomic_inc_int(&mo->ro_refcnt);
}

/*
 * rw_obj_free:
 *
 *	Drop a reference from a lock object.  If the last reference is being
 *	dropped, free the object and return true.  Otherwise, return false.
 */
int
rw_obj_free(struct rwlock *lock)
{
	struct rwlock_obj *mo = (struct rwlock_obj *)lock;

	KASSERTMSG(mo->ro_magic == RWLOCK_OBJ_MAGIC,
	    "%s: lock %p: mo->ro_magic (%#x) != RWLOCK_OBJ_MAGIC (%#x)",
	     __func__, mo, mo->ro_magic, RWLOCK_OBJ_MAGIC);
	KASSERTMSG(mo->ro_refcnt > 0,
	    "%s: lock %p: mo->ro_refcnt (%#x) == 0",
	     __func__, mo, mo->ro_refcnt);

	if (atomic_dec_int_nv(&mo->ro_refcnt) > 0) {
		return false;
	}
#if notyet
	WITNESS_DESTROY(&mo->ro_lock);
#endif
	pool_put(&rwlock_obj_pool, mo);
	return true;
}
