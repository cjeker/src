/*	$OpenBSD$ */

/*
 * Copyright (c) 2026 Claudio Jeker <claudio@openbsd.org>
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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <event.h>

#include "imsgev.h"

struct imsgev {
	struct imsgbuf		 ibuf;
	struct event		 rev;
	struct event		 wev;
	void			(*imsg_handler)(struct imsg *, void *);
	void			(*error_handler)(struct imsgbuf *,
				    void *, short, int);
	void			 *arg;
};

static void
imsgev_add(struct imsgbuf *imsgbuf, void *udata)
{
	struct imsgev *iev = udata;

	event_add(&iev->wev, NULL);
}

static void
imsgev_write(int fd, short event, void *arg)
{
	struct imsgev *iev = arg;
	struct imsgbuf *imsgbuf = &iev->ibuf;

	if (event & EV_WRITE) {
		if (imsgbuf_write(imsgbuf) == -1) {
			iev->error_handler(imsgbuf, iev->arg, EV_WRITE, errno);
			return;
		}
	}

	if (imsgbuf_queuelen(imsgbuf) == 0)
		event_del(&iev->wev);
}

static void
imsgev_read(int fd, short event, void *arg)
{
	struct imsgev *iev = arg;
	struct imsgbuf *imsgbuf = &iev->ibuf;
	struct imsg imsg;
	int n;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(imsgbuf)) == -1) {
			iev->error_handler(imsgbuf, iev->arg, EV_READ, errno);
			return;
		}
		if (n == 0) {
			iev->error_handler(imsgbuf, iev->arg, EV_READ, 0);
			return;
		}
	}

	for (;;) {
		if ((n = imsgbuf_get(imsgbuf, &imsg)) == -1) {
			iev->error_handler(imsgbuf, iev->arg, EV_READ, errno);
			return;
		}
		if (n == 0)
			break;

		iev->imsg_handler(&imsg, iev->arg);

		imsg_free(&imsg);
	}
}

struct imsgbuf *
imsgev_new(int fd, void (*imsg_handler)(struct imsg *, void *),
    void (*error_handler)(struct imsgbuf *imsgbuf, void *, short, int),
    void *arg)
{
	struct imsgev *iev;

	if ((iev = calloc(1, sizeof(struct imsgev))) == NULL)
		return NULL;

	if (imsgbuf_init(&iev->ibuf, fd) == -1) {
		free(iev);
		return NULL;
	}

	imsgbuf_set_userdata(&iev->ibuf, iev);
	imsgbuf_set_close_callback(&iev->ibuf, imsgev_add);
	iev->imsg_handler = imsg_handler;
	iev->error_handler = error_handler;
	iev->arg = arg;

	event_set(&iev->rev, fd, EV_READ | EV_PERSIST, imsgev_read, iev);
	event_set(&iev->wev, fd, EV_WRITE | EV_PERSIST, imsgev_write, iev);

	event_add(&iev->rev, NULL);
	return &iev->ibuf;
}

void
imsgev_free(struct imsgbuf *imsgbuf)
{
	struct imsgev *iev;

	iev = imsgbuf_get_userdata(imsgbuf);

	close(imsgbuf->fd);
	imsgbuf_clear(imsgbuf);

	event_del(&iev->rev);
	event_del(&iev->wev);
	free(iev);
}
