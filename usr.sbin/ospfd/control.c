/*	$OpenBSD: control.c,v 1.56 2026/08/03 18:48:44 claudio Exp $ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ospfd.h"
#include "ospf.h"
#include "ospfe.h"
#include "log.h"
#include "control.h"

TAILQ_HEAD(ctl_conns, ctl_conn)	ctl_conns = TAILQ_HEAD_INITIALIZER(ctl_conns);

#define	CONTROL_BACKLOG	5

struct ctl_conn	*control_connbyfd(int);
struct ctl_conn	*control_connbypid(pid_t);
void		 control_close(struct ctl_conn *);
void		 control_dispatch_imsg(struct imsg *, void *);
void		 control_dispatch_error(struct imsgbuf *, void *, short, int);

struct {
	struct event	ev;
	struct event	evt;
	int		fd;
} control_state;

int
control_check(char *path)
{
	struct sockaddr_un	 sun;
	int			 fd;

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		log_warn("control_check: socket check");
		return (-1);
	}

	if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
		log_warnx("control_check: socket in use");
		close(fd);
		return (-1);
	}

	close(fd);

	return (0);
}

int
control_init(char *path)
{
	struct sockaddr_un	 sun;
	int			 fd;
	mode_t			 old_umask;

	if ((fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    0)) == -1) {
		log_warn("control_init: socket");
		return (-1);
	}

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));

	if (unlink(path) == -1)
		if (errno != ENOENT) {
			log_warn("control_init: unlink %s", path);
			close(fd);
			return (-1);
		}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("control_init: bind: %s", path);
		close(fd);
		umask(old_umask);
		return (-1);
	}
	umask(old_umask);

	if (chmod(path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) == -1) {
		log_warn("control_init: chmod");
		close(fd);
		(void)unlink(path);
		return (-1);
	}

	return (fd);
}

int
control_listen(int fd)
{
	control_state.fd = fd;

	if (listen(control_state.fd, CONTROL_BACKLOG) == -1) {
		log_warn("control_listen: listen");
		return (-1);
	}

	event_set(&control_state.ev, control_state.fd, EV_READ,
	    control_accept, NULL);
	event_add(&control_state.ev, NULL);
	evtimer_set(&control_state.evt, control_accept, NULL);

	return (0);
}

void
control_cleanup(void)
{
	event_del(&control_state.ev);
	event_del(&control_state.evt);
}

void
control_accept(int listenfd, short event, void *bula)
{
	int			 connfd;
	socklen_t		 len;
	struct sockaddr_un	 sun;
	struct ctl_conn		*c;

	event_add(&control_state.ev, NULL);
	if ((event & EV_TIMEOUT))
		return;

	len = sizeof(sun);
	if ((connfd = accept4(listenfd, (struct sockaddr *)&sun, &len,
	    SOCK_CLOEXEC | SOCK_NONBLOCK)) == -1) {
		/*
		 * Pause accept if we are out of file descriptors, or
		 * libevent will haunt us here too.
		 */
		if (errno == ENFILE || errno == EMFILE) {
			struct timeval evtpause = { 1, 0 };

			event_del(&control_state.ev);
			evtimer_add(&control_state.evt, &evtpause);
		} else if (errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			log_warn("control_accept: accept");
		return;
	}

	if ((c = calloc(1, sizeof(struct ctl_conn))) == NULL) {
		log_warn("control_accept");
		close(connfd);
		return;
	}

	if ((c->imsgbuf = imsgev_new(connfd, control_dispatch_imsg,
	    control_dispatch_error, c)) == NULL) {
		log_warn("imsgbuf_init");
		close(connfd);
		free(c);
		return;
	}

	TAILQ_INSERT_TAIL(&ctl_conns, c, entry);
}

struct ctl_conn *
control_connbyfd(int fd)
{
	struct ctl_conn	*c;

	TAILQ_FOREACH(c, &ctl_conns, entry) {
		if (c->imsgbuf->fd == fd)
			break;
	}

	return (c);
}

struct ctl_conn *
control_connbypid(pid_t pid)
{
	struct ctl_conn	*c;

	TAILQ_FOREACH(c, &ctl_conns, entry) {
		if (c->imsgbuf->pid == pid)
			break;
	}

	return (c);
}

void
control_close(struct ctl_conn *c)
{
	TAILQ_REMOVE(&ctl_conns, c, entry);
	imsgev_free(c->imsgbuf);

	/* Some file descriptors are available again. */
	if (evtimer_pending(&control_state.evt, NULL)) {
		evtimer_del(&control_state.evt);
		event_add(&control_state.ev, NULL);
	}

	free(c);
}

void
control_dispatch_imsg(struct imsg *imsg, void *arg)
{
	struct ctl_conn	*c = arg;
	uint32_t	 type;
	pid_t		 pid;
	int		 verbose;
	unsigned int	 ifidx;

	c->imsgbuf->pid = pid = imsg_get_pid(imsg);
	type = imsg_get_type(imsg);
	switch (type) {
	case IMSG_CTL_FIB_COUPLE:
	case IMSG_CTL_FIB_DECOUPLE:
		ospfe_fib_update(type);
		/* FALLTHROUGH */
	case IMSG_CTL_FIB_RELOAD:
	case IMSG_CTL_RELOAD:
		ospfe_imsg_compose_parent(type, 0, NULL, 0);
		break;
	case IMSG_CTL_KROUTE:
	case IMSG_CTL_KROUTE_ADDR:
	case IMSG_CTL_IFINFO:
		ospfe_imsg_forward_parent(imsg);
		break;
	case IMSG_CTL_SHOW_INTERFACE:
		if (imsg_get_data(imsg, &ifidx, sizeof(ifidx)) == -1)
			break;

		ospfe_iface_ctl(c, ifidx);
		break;
	case IMSG_CTL_SHOW_DATABASE:
	case IMSG_CTL_SHOW_DB_EXT:
	case IMSG_CTL_SHOW_DB_NET:
	case IMSG_CTL_SHOW_DB_RTR:
	case IMSG_CTL_SHOW_DB_SELF:
	case IMSG_CTL_SHOW_DB_SUM:
	case IMSG_CTL_SHOW_DB_ASBR:
	case IMSG_CTL_SHOW_DB_OPAQ:
	case IMSG_CTL_SHOW_RIB:
	case IMSG_CTL_SHOW_SUM:
		ospfe_imsg_forward_rde(imsg);
		break;
	case IMSG_CTL_SHOW_NBR:
		ospfe_nbr_ctl(c);
		break;
	case IMSG_CTL_LOG_VERBOSE:
		if (imsg_get_data(imsg, &verbose, sizeof(verbose)) == -1)
			break;

		/* forward to other processes */
		ospfe_imsg_forward_parent(imsg);
		ospfe_imsg_forward_rde(imsg);
		log_setverbose(verbose);
		break;
	default:
		log_debug("control_dispatch_imsg: "
		    "error handling imsg %d", type);
		break;
	}
}

void
control_dispatch_error(struct imsgbuf *ibuf, void *arg, short event, int error)
{
	struct ctl_conn	*c = arg;

	/* silently discard session, ospfctl will complain to user */
	control_close(c);
}

int
control_imsg_relay(struct imsg *imsg)
{
	struct ctl_conn	*c;

	if ((c = control_connbypid(imsg_get_pid(imsg))) == NULL)
		return (0);

	return (imsg_forward(c->imsgbuf, imsg));
}
