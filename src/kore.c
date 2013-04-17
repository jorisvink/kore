/*
 * Copyright (c) 2013 Joris Vink <joris@coders.se>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/epoll.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kore.h"

#define EPOLL_EVENTS	500

static int	efd = -1;

static int	kore_server_bind(struct listener *, const char *, int);
static int	kore_server_accept(struct listener *);
static int	kore_connection_handle(struct connection *, int);
static int	kore_socket_nonblock(int);
static void	kore_event(int, int, void *);

int
main(int argc, char *argv[])
{
	struct connection	*c;
	struct listener		server;
	struct epoll_event	*events;
	int			n, i, *fd;

	if (argc != 3)
		fatal("Usage: kore [ip] [port]");

	if (!kore_server_bind(&server, argv[1], atoi(argv[2])))
		fatal("cannot bind to %s:%s", argv[1], argv[2]);

	if ((efd = epoll_create(1000)) == -1)
		fatal("epoll_create(): %s", errno_s);

	kore_event(server.fd, EPOLLIN, &server);
	events = kore_calloc(EPOLL_EVENTS, sizeof(struct epoll_event));
	for (;;) {
		n = epoll_wait(efd, events, EPOLL_EVENTS, -1);
		if (n == -1)
			fatal("epoll_wait(): %s", errno_s);

		for (i = 0; i < n; i++) {
			fd = (int *)events[i].data.ptr;

			if (events[i].events & EPOLLERR ||
			    events[i].events & EPOLLHUP) {
				if (*fd == server.fd)
					fatal("error on server socket");

				c = (struct connection *)events[i].data.ptr;
				continue;
			}

			if (*fd == server.fd) {
				kore_server_accept(&server);
			} else {
				c = (struct connection *)events[i].data.ptr;
				if (!kore_connection_handle(c, events[i].events))
					/* Disconnect. */;
			}
		}
	}

	close(server.fd);
	return (0);
}

static int
kore_server_bind(struct listener *l, const char *ip, int port)
{
	if ((l->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		kore_log("socket(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_socket_nonblock(l->fd)) {
		close(l->fd);
		return (KORE_RESULT_ERROR);
	}

	memset(&(l->sin), 0, sizeof(l->sin));
	l->sin.sin_family = AF_INET;
	l->sin.sin_port = htons(port);
	l->sin.sin_addr.s_addr = inet_addr(ip);

	if (bind(l->fd, (struct sockaddr *)&(l->sin), sizeof(l->sin)) == -1) {
		close(l->fd);
		kore_log("bind(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (listen(l->fd, 50) == -1) {
		close(l->fd);
		kore_log("listen(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static int
kore_server_accept(struct listener *l)
{
	socklen_t		len;
	struct connection	*c;

	len = sizeof(struct sockaddr_in);
	c = (struct connection *)kore_malloc(sizeof(*c));
	if ((c->fd = accept(l->fd, (struct sockaddr *)&(c->sin), &len)) == -1) {
		free(c);
		kore_log("accept(): %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	if (!kore_socket_nonblock(c->fd)) {
		close(c->fd);
		free(c);
		return (KORE_RESULT_ERROR);
	}

	c->owner = l;
	TAILQ_INIT(&(c->send_queue));
	TAILQ_INIT(&(c->recv_queue));
	kore_event(c->fd, EPOLLIN | EPOLLET, c);
	kore_log("new connection from %s", inet_ntoa(c->sin.sin_addr));

	return (KORE_RESULT_OK);
}

static int
kore_connection_handle(struct connection *c, int flags)
{
	return (KORE_RESULT_OK);
}

static int
kore_socket_nonblock(int fd)
{
	int		flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
		kore_log("fcntl(): F_GETFL %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		kore_log("fcntl(): F_SETFL %s", errno_s);
		return (KORE_RESULT_ERROR);
	}

	return (KORE_RESULT_OK);
}

static void
kore_event(int fd, int flags, void *udata)
{
	struct epoll_event	evt;

	evt.events = flags;
	evt.data.ptr = udata;
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &evt) == -1)
		fatal("epoll_ctl(): %s", errno_s);
}
