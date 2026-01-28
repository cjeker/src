/* $OpenBSD$ */

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

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/resource.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <err.h>

#include <event.h>

#include "../../sys/sys/lltrace.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define DEV_KUTRACE "/dev/lltrace"

#define NRINGS_DEFAULT	256 /* 256 * 8192 * 8 is 16MB */

struct lltrace;

struct mode {
	const char	  *name;
	void		*(*setup)(struct lltrace *, int, char **);
	int		 (*run)(struct lltrace *);
};

static void	 *mode_kill_setup(struct lltrace *, int, char **);
static int	  mode_kill_run(struct lltrace *);

static const struct mode mode_kill = {
	"kill",		mode_kill_setup,	mode_kill_run
};

static void		 *mode_wait_setup(struct lltrace *, int, char **);
static int		  mode_wait_run(struct lltrace *);
static void		 *mode_exec_setup(struct lltrace *, int, char **);
static int		  mode_exec_run(struct lltrace *);

static const struct mode modes[] = {
	{ "wait",	mode_wait_setup,	mode_wait_run },
	{ "exec",	mode_exec_setup,	mode_exec_run },
};

static const struct mode *
			 mode_lookup(const char *);
static const char	*outfile_default(void);

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-v] [-m blen] [-o output] [command]\n",
	    __progname);
	fprintf(stderr, "       %s wait seconds\n", __progname);
	fprintf(stderr, "       %s exec program ...\n", __progname);

	exit(-1);
}

struct lltrace {
	const char	*outfile;
	int		 dv; /* /dev/lltrace fd */
	int		 of; /* outfile fd */
	void		*mode;

	struct event	 dv_ev;	/* handle reading from the kernel */

	unsigned int	 blen;
	size_t		 nbuffers;
	struct lltrace_buffer
			*buffers;
	size_t		 buffer_idx;

	uint64_t	 nsec_first;
	uint64_t	 nsec_last;
	uint64_t	 count_buffers;
	uint64_t	 count_slots;
	uint64_t	 count_drops;
};

static void		 lltrace_start(struct lltrace *);
static void		 lltrace_stop(struct lltrace *);

static void		 lltrace_read(int, short, void *);
static void		 lltrace_flush(struct lltrace *);

int
main(int argc, char *argv[])
{
	const struct mode *mode = &mode_kill;
	int ch;
	const char *errstr;
	int verbose = 0;
	int prio;

	struct lltrace lltrace = {
		.outfile = NULL,
		.blen = 0,
		.nbuffers = NRINGS_DEFAULT,

		.nsec_first = ~0,
		.nsec_last = 0,
		.count_buffers = 0,
		.count_slots = 0,
		.count_drops = 0,
	};
	struct lltrace *llt = &lltrace;

	while ((ch = getopt(argc, argv, "m:n:o:v")) != -1) {
		switch (ch) {
		case 'm':
			llt->blen = strtonum(optarg,
			    LLTRACE_BLEN_MIN, LLTRACE_BLEN_MAX, &errstr);
			if (errstr != NULL) {
				errx(1, "kernel buffer len %s: %s",
				    optarg, errstr);
			}
			break;
		case 'n':
			llt->nbuffers = strtonum(optarg, 4, 4096, &errstr);
			if (errstr != NULL) {
				errx(1, "number of buffers %s: %s",
				    optarg, errstr);
			}
			break;
		case 'o':
			llt->outfile = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	optreset = optind = opterr = 1; /* kill mode has to be careful */

	if (argc > 0) {
		mode = mode_lookup(argv[0]);
		if (mode == NULL)
			errx(1, "unknown mode %s", argv[0]);
	}

	if (llt->outfile == NULL)
		llt->outfile = outfile_default();

	event_init();

	llt->mode = (*mode->setup)(llt, argc, argv);

	llt->dv = open(DEV_KUTRACE, O_NONBLOCK|O_RDWR|O_CLOEXEC);
	if (llt->dv == -1)
		err(1, "%s", DEV_KUTRACE);

	if (llt->blen != 0) {
		if (ioctl(llt->dv, LLTIOCSBLEN, &llt->blen) == -1)
			err(1, "set kernel buffer len %u", llt->blen);
	}

	event_set(&llt->dv_ev, llt->dv, EV_READ|EV_PERSIST,
	    lltrace_read, llt);

	llt->of = open(llt->outfile, O_WRONLY|O_CREAT|O_CLOEXEC|O_TRUNC, 0640);
	if (llt->of == -1)
		err(1, "open %s", llt->outfile);

	llt->buffers = calloc(llt->nbuffers, sizeof(*llt->buffers));
	if (llt->buffers == NULL)
		err(1, "unable to allocate %zu buffers", llt->nbuffers);

	llt->buffer_idx = 0;

	if ((*mode->run)(llt) == -1)
		exit(1);

	prio = getpriority(PRIO_PROCESS, 0);
	if (setpriority(PRIO_PROCESS, 0, -20) == -1)
		err(1, "setpriority -20");

	lltrace_start(llt);

	event_dispatch();

	if (setpriority(PRIO_PROCESS, 0, prio) == -1)
		err(1, "setpriority %d", prio);
	
	if (llt->buffer_idx != 0)
		lltrace_flush(llt);

	if (verbose) {
		uint64_t diff = llt->nsec_last - llt->nsec_first;
		double interval = (double)diff / 1000000000.0;
		int mib[] = { CTL_HW, HW_NCPU };
		int ncpus;
		size_t ncpuslen = sizeof(ncpus);

		if (sysctl(mib, nitems(mib), &ncpus, &ncpuslen, NULL, 0) == -1)
			err(1, "sysctl hw.ncpus");

		printf("output file: %s\n", llt->outfile);
		printf("interval: %.03lfs, ncpus: %d\n", interval, ncpus);
		printf("buffers: %llu (%.01lf/cpu/s), "
		    "slots: %llu (%.01lf/cpu/s)\n",
		    llt->count_buffers, llt->count_buffers / interval / ncpus,
		    llt->count_slots, llt->count_slots / interval / ncpus);
		printf("drops: %llu (%.01lf/cpu/s)\n",
		    llt->count_drops, llt->count_drops / interval / ncpus);
	}

	return (0);
}

static void
lltrace_start(struct lltrace *llt)
{
	event_add(&llt->dv_ev, NULL);

	if (ioctl(llt->dv, LLTIOCSTART) == -1)
		err(1, "lltrace start");
}

static void
lltrace_flush(struct lltrace *llt)
{
	size_t len;
	ssize_t rv;

	len = llt->buffer_idx * sizeof(*llt->buffers);
	rv = write(llt->of, llt->buffers, len);
	if (rv == -1)
		err(1, "%s write", llt->outfile);

	if ((size_t)rv < len) {
		errx(1, "%s write short (%zd/%zu bytes)",
		    llt->outfile, rv, len);
	}
}

static int
lltrace_read_one(struct lltrace *llt)
{
	struct lltrace_buffer *buffer;
	ssize_t rv;
	uint64_t nsec;

	if (llt->buffer_idx >= llt->nbuffers) {
		size_t i, j;

		lltrace_flush(llt);

		/* reset */
		llt->buffer_idx = 0;

		/*
		 * memset(llt->buffers, 0,
		 *     llt->nbuffers * sizeof(*llt->buffers));
		 */
		for (i = 0; i < llt->nbuffers; i++) {
			buffer = llt->buffers + i;
			
			for (j = 0; j < nitems(buffer->llt_slots); j++)
				buffer->llt_slots[j] = 0;
		}
	}

	buffer = llt->buffers + llt->buffer_idx;
	rv = read(llt->dv, buffer, sizeof(*buffer));
	if (rv == -1) {
		switch (errno) {
		case EAGAIN:
			/* try again later */
			return (EAGAIN);
		case ENOENT:
			/* we're done */
			event_del(&llt->dv_ev);
			return (ENOENT);
		default:
			err(1, "%s read", DEV_KUTRACE);
			/* NOTREACHED */
		}
	}

	if (rv == 0) {
		/* we're done */
		event_del(&llt->dv_ev);
		return (ENOENT);
	}

	llt->buffer_idx++;

	nsec = buffer->llt_slots[3];
	if (nsec < llt->nsec_first)
		llt->nsec_first = nsec;

	nsec = buffer->llt_slots[5];
	if (nsec > llt->nsec_last)
		llt->nsec_last = nsec;

	llt->count_buffers++;
	llt->count_slots += rv / sizeof(uint64_t);
	//llt->count_drops += buffer->slots[7];

	return (0);
}

static void
lltrace_read(int dv, short events, void *arg)
{
	struct lltrace *llt = arg;

	lltrace_read_one(llt);
}

static void
lltrace_stop(struct lltrace *llt)
{
	int error;

	if (ioctl(llt->dv, LLTIOCSTOP) == -1) {
		if (errno != EALREADY)
			err(1, "lltrace stop");
	}

	do {
		error = lltrace_read_one(llt);
	} while (error == 0);

	event_del(&llt->dv_ev);
}

static const char *
outfile_default(void)
{
	extern char *__progname;
	char host[MAXHOSTNAMELEN];
	time_t now;
	struct tm *tm;
	char *outfile;

	if (gethostname(host, sizeof(host)) == -1)
		err(1, "gethostname");

	now = time(NULL);

	tm = localtime(&now);

	if (asprintf(&outfile, "%s_%04d%02d%02d_%02d%02d%02d_%s.lltrace",
	    __progname,
	    tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec,
	    host) == -1)
		errx(1, "error generating default output filename");

	return (outfile);
}

#if 0
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
hexdump(const void *d, size_t datalen)
{
	const uint8_t *data = d;
	size_t i, j = 0;

	for (i = 0; i < datalen; i += j) {
#if 0
		printf("%04zu: ", i);
		for (j = 0; j < 16 && i+j < datalen; j++)
			printf("%02x ", data[i + j]);
		while (j++ < 16)
			printf("   ");
#endif
		printf("|");

		for (j = 0; j < 16 && i+j < datalen; j++)
			putchar(printable(data[i + j]));
		printf("|\n");
	}
}
#endif

static const struct mode *
mode_lookup(const char *name)
{
	size_t i;

	for (i = 0; i < nitems(modes); i++) {
		const struct mode *mode = &modes[i];

		if (strcmp(mode->name, name) == 0)
			return (mode);
	}

	return (NULL);
}

static void
mode_kill_event(int nil, short events, void *arg)
{
	struct lltrace *llt = arg;
	struct event *ev = llt->mode;

	fprintf(stdout, "lltrace stopped\n");
	fflush(stdout);

	event_del(ev);

	lltrace_stop(llt);
}

static void *
mode_kill_setup(struct lltrace *llt, int argc, char *argv[])
{
	struct event *ev;

	if (argc != 0)
		usage();

	ev = malloc(sizeof(*ev));
	if (ev == NULL)
		err(1, NULL);

	signal_set(ev, SIGINT, mode_kill_event, llt);
	return (ev);
}

static int
mode_kill_run(struct lltrace *llt)
{
	struct event *ev = llt->mode;

	signal_add(ev, NULL);

	fprintf(stdout, "lltrace starting, press Ctrl-C to end...\n");
	fflush(stdout);

	return (0);
}

/*
 * lltrace for specified number of seconds.
 */

struct mode_wait_state {
	struct lltrace	*llt;
	struct timeval	tv;
	struct event	tmo;
	struct event	sig;
};

static void
mode_wait_tmo(int wat, short events, void *arg)
{
	struct mode_wait_state *state = arg;
	struct lltrace *llt = state->llt;

	signal_del(&state->sig);
	lltrace_stop(llt);
}

static void
mode_wait_sig(int wat, short events, void *arg)
{
	struct mode_wait_state *state = arg;
	struct lltrace *llt = state->llt;

	evtimer_del(&state->tmo);
	signal_del(&state->sig);
	lltrace_stop(llt);
}

static void *
mode_wait_setup(struct lltrace *llt, int argc, char *argv[])
{
	struct mode_wait_state *state;
	const char *errstr;

	if (argc != 2)
		usage();

	state = malloc(sizeof(*state));
	if (state == NULL)
		err(1, NULL);

	state->llt = llt;

	state->tv.tv_sec = strtonum(argv[1], 1, 600, &errstr);
	if (errstr != NULL)
		errx(1, "wait time %s: %s", argv[1], errstr);

	state->tv.tv_usec = 0;

	evtimer_set(&state->tmo, mode_wait_tmo, state);
	signal_set(&state->sig, SIGINT, mode_wait_sig, state);

	return (state);
}

static int
mode_wait_run(struct lltrace *llt)
{
	struct mode_wait_state *state = llt->mode;

	evtimer_add(&state->tmo, &state->tv);
	signal_add(&state->sig, NULL);

	return (0);
}

/*
 * trace the execution of a (child) program
 */

struct mode_exec_state {
	struct lltrace	*llt;

	char		**argv;

	pid_t		pid;
	struct event	sigchld;
	struct event	sigint;

	uid_t		uid;
	gid_t		gid;
	gid_t		groups[NGROUPS_MAX];
	int		ngroups;
};

static void
mode_exec_sig(int wat, short events, void *arg)
{
	struct mode_exec_state *state = arg;
	struct lltrace *llt = state->llt;

	/* do we check the pid? */

	signal_del(&state->sigchld);
	signal_del(&state->sigint);
	lltrace_stop(llt);
}

static void *
mode_exec_setup(struct lltrace *llt, int argc, char *argv[])
{
	struct mode_exec_state *state;
	const char *user = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "u:")) != -1) {
		switch (ch) {
		case 'u':
			user = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		warnx("no command specified");
		usage();
	}

	state = malloc(sizeof(*state));
	if (state == NULL)
		err(1, NULL);

	state->llt = llt;
	state->argv = argv;
	state->uid = 0;
	state->pid = -1; /* not yet */
	signal_set(&state->sigchld, SIGCHLD, mode_exec_sig, state);
	signal_set(&state->sigint, SIGINT, mode_exec_sig, state);

	if (user != NULL) {
		struct passwd *pw;

		pw = getpwnam(user);
		if (pw == NULL)
			errx(1, "unable to lookup user %s", user);

		state->uid = pw->pw_uid;
		state->gid = pw->pw_gid;

		endpwent();

		state->ngroups = nitems(state->groups);
		if (getgrouplist(user, pw->pw_gid,
		    state->groups, &state->ngroups) == -1)
			errx(1, "unable to get groups for user %s", user);
	}

	return (state);
}

static int
mode_exec_run(struct lltrace *llt)
{
	struct mode_exec_state *state = llt->mode;

	signal_add(&state->sigchld, NULL);
	signal_add(&state->sigint, NULL);

	state->pid = fork();
	switch (state->pid) {
	case -1:
		err(1, "unable to fork");
		/* NOTREACHED */
	case 0: /* child */
		break;
	default: /* parent */
		return (0);
	}

	if (state->uid != 0) {
		if (setresgid(state->gid, state->gid, state->gid) == -1)
			err(1, "setresgid %d", state->gid);

		if (setgroups(state->ngroups, state->groups) == -1)
			err(1, "setgroups");

		if (setresuid(state->uid, state->uid, state->uid) == -1)
			err(1, "setresuid %d", state->uid);
	}

	execvp(state->argv[0], state->argv);

	err(1, "exec %s", state->argv[0]);
	return (-1);
}
