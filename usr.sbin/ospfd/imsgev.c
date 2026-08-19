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

#include <stdlib.h>
#include <unistd.h>

#include <event.h>

#include "imsgev.h"

struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	short			 events;
};

void
imsg_event_add(struct imsgbuf *imsgbuf, void *udata)
{
	struct imsgev *iev = udata;

	iev->events = EV_READ;
	if (imsgbuf_queuelen(&iev->ibuf) > 0)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler,
	    &iev->ibuf);
	event_add(&iev->ev, NULL);
}

struct imsgbuf *
imsgev_new(int fd, void (*handler)(int, short, void *))
{
	struct imsgev *iev;

	if ((iev = calloc(1, sizeof(struct imsgev))) == NULL)
		return NULL;

	if (imsgbuf_init(&iev->ibuf, fd) == -1) {
		free(iev);
		return NULL;
	}

	imsgbuf_set_userdata(&iev->ibuf, iev);
	imsgbuf_set_close_callback(&iev->ibuf, imsg_event_add);
	iev->handler = handler;

	iev->events = EV_READ;
	event_set(&iev->ev, fd, iev->events, iev->handler, &iev->ibuf);
	event_add(&iev->ev, NULL);

	return &iev->ibuf;
}

void
imsgev_free(struct imsgbuf *imsgbuf)
{
	struct imsgev *iev;

	iev = imsgbuf_get_userdata(imsgbuf);

	close(imsgbuf->fd);
	imsgbuf_clear(imsgbuf);

	event_del(&iev->ev);
	free(iev);
}
