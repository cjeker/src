/*	$OpenBSD: flockfile.c,v 1.9 2016/05/07 19:05:22 guenther Exp $	*/

#include <stdio.h>
#include "local.h"

static inline struct __rcmtx *
frcmtx(FILE *fp)
{
	return &_EXT(fp)->_lock;
}

void
flockfile(FILE *fp)
{
	if (__isthreaded) {
		struct __rcmtx *rcm = frcmtx(fp);
		__rcmtx_enter(rcm);
	}
}
DEF_WEAK(flockfile);

int
ftrylockfile(FILE *fp)
{
	if (__isthreaded) {
		struct __rcmtx *rcm = frcmtx(fp);
		return __rcmtx_enter_try(rcm);
	}

	return 0;
}
DEF_WEAK(ftrylockfile);

void
funlockfile(FILE *fp)
{
	if (__isthreaded) {
		struct __rcmtx *rcm = frcmtx(fp);
		__rcmtx_leave(rcm);
	}
}
DEF_WEAK(funlockfile);
