#	$OpenBSD: GENERIC.MP,v 1.5 2023/05/25 19:32:34 kurt Exp $

include "arch/sparc64/conf/GENERIC"

option	MULTIPROCESSOR
option	MP_LOCKDEBUG
option	WITNESS
option	DDB_SAFE_CONSOLE
option	SPLASSERT_WATCH

cpu*	at mainbus?
cpu*	at ssm?
cpu*	at cmp?
cpu*	at core?
