/*	$OpenBSD: file.c,v 1.28 2024/12/20 07:35:56 ratchov Exp $	*/
/*
 * Copyright (c) 2008-2012 Alexandre Ratchov <alex@caoua.org>
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
 * non-blocking file i/o module: each file can be read or written (or
 * both). To achieve non-blocking io, we simply use the poll() syscall
 * in an event loop and dispatch events to sub-modules.
 *
 * the module also provides trivial timeout implementation,
 * derived from:
 *
 * 	anoncvs@moule.caoua.org:/midish
 *
 *		midish/timo.c rev 1.18
 * 		midish/mdep.c rev 1.71
 *
 * A timeout is used to schedule the call of a routine (the callback)
 * there is a global list of timeouts that is processed inside the
 * event loop. Timeouts work as follows:
 *
 *	first the timo structure must be initialized with timo_set()
 *
 *	then the timeout is scheduled (only once) with timo_add()
 *
 *	if the timeout expires, the call-back is called; then it can
 *	be scheduled again if needed. It's OK to reschedule it again
 *	from the callback
 *
 *	the timeout can be aborted with timo_del(), it is OK to try to
 *	abort a timeout that has expired
 *
 */

#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "file.h"
#include "utils.h"

#define MAXFDS 100
#define TIMER_MSEC 5

void timo_update(unsigned int);
void timo_init(void);
void timo_done(void);
int file_process(struct file *, struct pollfd *);

struct timespec file_ts;
struct file *file_list;
struct timo *timo_queue;
unsigned int timo_abstime;
int file_slowaccept = 0, file_nfds;
#ifdef DEBUG
long long file_wtime, file_utime;
#endif

/*
 * initialise a timeout structure, arguments are callback and argument
 * that will be passed to the callback
 */
void
timo_set(struct timo *o, void (*cb)(void *), void *arg)
{
	o->cb = cb;
	o->arg = arg;
	o->set = 0;
}

/*
 * schedule the callback in 'delta' 24-th of microseconds. The timeout
 * must not be already scheduled
 */
void
timo_add(struct timo *o, unsigned int delta)
{
	struct timo **i;
	unsigned int val;
	int diff;

#ifdef DEBUG
	if (o->set) {
		logx(0, "timo_add: already set");
		panic();
	}
	if (delta == 0) {
		logx(0, "timo_add: zero timeout is evil");
		panic();
	}
#endif
	val = timo_abstime + delta;
	for (i = &timo_queue; *i != NULL; i = &(*i)->next) {
		diff = (*i)->val - val;
		if (diff > 0) {
			break;
		}
	}
	o->set = 1;
	o->val = val;
	o->next = *i;
	*i = o;
}

/*
 * abort a scheduled timeout
 */
void
timo_del(struct timo *o)
{
	struct timo **i;

	for (i = &timo_queue; *i != NULL; i = &(*i)->next) {
		if (*i == o) {
			*i = o->next;
			o->set = 0;
			return;
		}
	}
#ifdef DEBUG
	logx(4, "timo_del: not found");
#endif
}

/*
 * routine to be called by the timer when 'delta' 24-th of microsecond
 * elapsed. This routine updates time reference used by timeouts and
 * calls expired timeouts
 */
void
timo_update(unsigned int delta)
{
	struct timo *to;
	int diff;

	/*
	 * update time reference
	 */
	timo_abstime += delta;

	/*
	 * remove from the queue and run expired timeouts
	 */
	while (timo_queue != NULL) {
		/*
		 * there is no overflow here because + and - are
		 * modulo 2^32, they are the same for both signed and
		 * unsigned integers
		 */
		diff = timo_queue->val - timo_abstime;
		if (diff > 0)
			break;
		to = timo_queue;
		timo_queue = to->next;
		to->set = 0;
		to->cb(to->arg);
	}
}

/*
 * initialize timeout queue
 */
void
timo_init(void)
{
	timo_queue = NULL;
	timo_abstime = 0;
}

/*
 * destroy timeout queue
 */
void
timo_done(void)
{
#ifdef DEBUG
	if (timo_queue != NULL) {
		logx(0, "timo_done: timo_queue not empty!");
		panic();
	}
#endif
	timo_queue = (struct timo *)0xdeadbeef;
}

struct file *
file_new(struct fileops *ops, void *arg, char *name, unsigned int nfds)
{
	struct file *f;

	if (file_nfds + nfds > MAXFDS) {
#ifdef DEBUG
		logx(1, "%s: too many polled files", name);
#endif
		return NULL;
	}
	f = xmalloc(sizeof(struct file));
	f->max_nfds = nfds;
	f->nfds = 0;
	f->ops = ops;
	f->arg = arg;
	f->name = name;
	f->state = FILE_INIT;
	f->next = file_list;
	file_list = f;
#ifdef DEBUG
	logx(3, "%s: created", f->name);
#endif
	file_nfds += f->max_nfds;
	return f;
}

void
file_del(struct file *f)
{
#ifdef DEBUG
	if (f->state == FILE_ZOMB) {
		logx(0, "%s: %s: bad state in file_del", __func__, f->name);
		panic();
	}
#endif
	file_nfds -= f->max_nfds;
	f->state = FILE_ZOMB;
#ifdef DEBUG
	logx(3, "%s: destroyed", f->name);
#endif
}

int
file_process(struct file *f, struct pollfd *pfd)
{
	int rc, revents;
#ifdef DEBUG
	struct timespec ts0, ts1;
	long us;
#endif

#ifdef DEBUG
	if (log_level >= 3)
		clock_gettime(CLOCK_UPTIME, &ts0);
#endif
	rc = 0;
	revents = (f->state != FILE_ZOMB) ?
	    f->ops->revents(f->arg, pfd) : 0;
	if ((revents & POLLHUP) && (f->state != FILE_ZOMB)) {
		f->ops->hup(f->arg);
		rc = 1;
	}
	if ((revents & POLLIN) && (f->state != FILE_ZOMB)) {
		f->ops->in(f->arg);
		rc = 1;
	}
	if ((revents & POLLOUT) && (f->state != FILE_ZOMB)) {
		f->ops->out(f->arg);
		rc = 1;
	}
#ifdef DEBUG
	if (log_level >= 3) {
		clock_gettime(CLOCK_UPTIME, &ts1);
		us = 1000000L * (ts1.tv_sec - ts0.tv_sec);
		us += (ts1.tv_nsec - ts0.tv_nsec) / 1000;
		if (us >= 5000)
			logx(4, "%s: processed in %luus", f->name, us);
	}
#endif
	return rc;
}

#ifdef DEBUG
size_t
filelist_fmt(char *buf, size_t size, struct pollfd *pfd, int ret)
{
	struct file *f;
	char *p = buf, *end = buf + size;
	const char *sep = "";
	int i;

	for (f = file_list; f != NULL; f = f->next) {
		p += snprintf(p, p < end ? end - p : 0, "%s%s:", sep, f->name);
		for (i = 0; i < f->nfds; i++) {
			p += snprintf(p, p < end ? end - p : 0, " 0x%x",
			    ret ? pfd->revents : pfd->events);
			pfd++;
		}
		sep = ", ";
	}
	return p - buf;
}
#endif

int
file_poll(void)
{
	struct pollfd pfds[MAXFDS], *pfd;
	struct file *f, **pf;
	struct timespec ts;
#ifdef DEBUG
	struct timespec sleepts;
	char str[128];
#endif
	long long delta_nsec;
	int nfds, res, timo;

	/*
	 * cleanup zombies
	 */
	pf = &file_list;
	while ((f = *pf) != NULL) {
		if (f->state == FILE_ZOMB) {
			*pf = f->next;
			xfree(f);
		} else
			pf = &f->next;
	}

	if (file_list == NULL && timo_queue == NULL) {
#ifdef DEBUG
		logx(3, "nothing to do...");
#endif
		return 0;
	}

	/*
	 * fill pollfd structures
	 */
	nfds = 0;
	for (f = file_list; f != NULL; f = f->next) {
		f->nfds = f->ops->pollfd(f->arg, pfds + nfds);
		if (f->nfds == 0)
			continue;
		nfds += f->nfds;
	}
#ifdef DEBUG
	logx(4, "poll [%s]", (filelist_fmt(str, sizeof(str), pfds, 0), str));
#endif

	/*
	 * process files that do not rely on poll
	 */
	res = 0;
	for (f = file_list; f != NULL; f = f->next) {
		if (f->nfds > 0)
			continue;
		res |= file_process(f, NULL);
	}
	/*
	 * The processing may have changed the poll(2) conditions of
	 * other files, so restart the loop to force their poll(2) event
	 * masks to be reevaluated.
	 */
	if (res)
		return 1;

	/*
	 * Sleep. Calculate the number of milliseconds poll(2) must
	 * wait before the timo_update() needs to be called. If there are
	 * no timeouts scheduled, then call poll(2) with infinite
	 * timeout (i.e -1).
	 */
#ifdef DEBUG
	clock_gettime(CLOCK_UPTIME, &sleepts);
	file_utime += 1000000000LL * (sleepts.tv_sec - file_ts.tv_sec);
	file_utime += sleepts.tv_nsec - file_ts.tv_nsec;
#endif
	if (timo_queue != NULL) {
		timo = ((int)timo_queue->val - (int)timo_abstime) / 1000;
		if (timo < TIMER_MSEC)
			timo = TIMER_MSEC;
	} else
		timo = -1;
	log_flush();
	res = poll(pfds, nfds, timo);
	if (res == -1) {
		if (errno != EINTR) {
			logx(0, "poll failed");
			panic();
		}
		return 1;
	}

	/*
	 * run timeouts
	 */
	clock_gettime(CLOCK_UPTIME, &ts);
#ifdef DEBUG
	file_wtime += 1000000000LL * (ts.tv_sec - sleepts.tv_sec);
	file_wtime += ts.tv_nsec - sleepts.tv_nsec;
#endif
	if (timo_queue) {
		delta_nsec = 1000000000LL * (ts.tv_sec - file_ts.tv_sec);
		delta_nsec += ts.tv_nsec - file_ts.tv_nsec;
		if (delta_nsec >= 0 && delta_nsec < 60000000000LL)
			timo_update(delta_nsec / 1000);
		else
			logx(2, "out-of-bounds clock delta");
	}
	file_ts = ts;

	/*
	 * process files that rely on poll
	 */
	pfd = pfds;
	for (f = file_list; f != NULL; f = f->next) {
		if (f->nfds == 0)
			continue;
		file_process(f, pfd);
		pfd += f->nfds;
	}
	return 1;
}

void
filelist_init(void)
{
	sigset_t set;

	if (clock_gettime(CLOCK_UPTIME, &file_ts) == -1) {
		logx(0, "filelist_init: CLOCK_UPTIME unsupported");
		panic();
	}
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigprocmask(SIG_BLOCK, &set, NULL);
	file_list = NULL;
	log_sync = 0;
	timo_init();
}

void
filelist_done(void)
{
#ifdef DEBUG
	struct file *f;

	if (file_list != NULL) {
		for (f = file_list; f != NULL; f = f->next)
			logx(0, "%s: not closed", f->name);
		panic();
	}
	log_sync = 1;
	log_flush();
#endif
	timo_done();
}
