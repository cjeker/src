/*	$OpenBSD: tracepoint.h,v 1.2 2022/06/28 09:32:28 bluhm Exp $ */

/*
 * Copyright (c) 2019 Martin Pieuchot <mpi@openbsd.org>
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

#ifndef _SYS_TRACEPOINT_H_
#define	_SYS_TRACEPOINT_H_

#ifdef _KERNEL

#include "dt.h"
#if NDT > 0
#include <dev/dt/dtvar.h>

#define TRACEPOINT(func, name, args...)	DT_STATIC_ENTER(func, name, args)
#define TRACEINDEX(func, index, args...) DT_INDEX_ENTER(func, index, args)

#else /* NDT > 0 */

#define TRACEPOINT(func, name, args...)
#define TRACEINDEX(func, index, args...)

#endif /* NDT > 0 */

#include "llt.h"
#if NLLT > 0
#include <sys/lltrace.h>

#define LLTRACE_SPC(_spc, _fn, ...) {					\
	struct lltrace_cpu *_llt = lltrace_enter_spc((_spc));		\
	if (_llt != NULL)						\
		(_fn)(_llt __VA_OPT__(,) __VA_ARGS__);			\
} while (0)

#define LLTRACE_CPU(_ci, _fn, ...) {					\
	struct lltrace_cpu *_llt = lltrace_enter_cpu((_ci));		\
	if (_llt != NULL)						\
		(_fn)(_llt __VA_OPT__(,) __VA_ARGS__);			\
} while (0)

#define LLTRACE(_fn, ...) {						\
	struct lltrace_cpu *_llt = lltrace_enter();			\
	if (_llt != NULL)						\
		(_fn)(_llt __VA_OPT__(,) __VA_ARGS__);			\
} while (0)

#else /* NLLT > 0 */

#define LLTRACE(_fn, ...)

#endif /* NLLT > 0 */
#endif /* _KERNEL */
#endif /* _SYS_TRACEPOINT_H_ */
