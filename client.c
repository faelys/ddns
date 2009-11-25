/* client.c - dynamic DNS client */

/*
 * Copyright (c) 2009, Natacha Porté
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

#include "log.h"
#include "message.h"
#include "sexp.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


struct client_options {
	struct buf	*host;
	struct buf	*port;
	struct buf	*name;
	struct buf	*key;
	int		 interval; };

#define DEFAULT_OPT { 0, 0, 0, 0, 0 }



static void
free_options(struct client_options *opt) {
	if (!opt) return;
	bufrelease(opt->host);
	bufrelease(opt->port);
	bufrelease(opt->name);
	bufrelease(opt->key); }



static int
parse_options(struct client_options *opt, struct sexp *sx) {
	struct sexp *s;
	struct client_options nopt = DEFAULT_OPT;

	/* reading value from S-expression */
	for (s = sx; s; s = s->next)
		if (!s->list || !s->list->node) continue;
		else if (!bufcmps(s->list->node, "server")) {
			if (s->list->next) {
				bufset(&nopt.host, s->list->next->node);
			if (s->list->next->next)
				bufset(&nopt.port, s->list->next->next->node);}}
		else if (!bufcmps(s->list->node, "name")) {
			if (s->list->next)
				bufset(&nopt.name, s->list->next->node); }
		else if (!bufcmps(s->list->node, "key")) {
			if (s->list->next)
				bufset(&nopt.key, s->list->next->node); }
		else if (!bufcmps(s->list->node, "interval")) {
			if (s->list->next)
				nopt.interval = buftoi(s->list->next->node,
								0, 0); }
		else log_c_bad_cmd(s->list->node);

	/* conformity checks */
	if (!nopt.host || !nopt.host->size
	||  !nopt.port || !nopt.port->size
	||  !nopt.name || !nopt.name->size
	||  !nopt.key  || !nopt.key->size) {
		free_options(&nopt);
		return 0; }

	/* NUL termination */
	bufnullterm(nopt.host);
	bufnullterm(nopt.port);

	/* output of the options */
	free_options(opt);
	*opt = nopt;
	return 1; }



static int
connect_socket(int socket, struct client_options *opt) {
	struct addrinfo hints, *res;
	int ret;

	/* address lookup */
	memset(&hints, 0, sizeof hints);
	bufnullterm(opt->host);
	bufnullterm(opt->port);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	ret = getaddrinfo(opt->host->data, opt->port->data, &hints, &res);
	if (ret) {
		log_c_getaddrinfo(opt->host->data, opt->port->data, ret);
		return 0; }
	if (res->ai_next) {
		log_c_ambiguous_addr(opt->host->data, opt->port->data, res);
		freeaddrinfo(res);
		return 0; }

	/* socket connection */
	if (connect(socket, res->ai_addr, res->ai_addrlen) < 0) {
		log_c_connect(opt->host->data, opt->port->data, res);
		freeaddrinfo(res);
		return 0; }

	/* clean-up */
	freeaddrinfo(res);
	return 1; }



static int
send_message(int socket, struct ddns_message *msg, struct buf *key) {
	unsigned char data[MAX_MSG_SIZE];
	size_t datalen;
	ssize_t ret;

	datalen = encode_message(data, sizeof data, msg, key->data, key->size);
	if (!datalen) return 0;
	ret = send(socket, data, datalen, 0);
	if (ret < 0) {
		log_c_send_fail(data, datalen);
		return 0; }
	else if (ret < datalen) {
		 log_c_send_short(data, datalen, ret);
		return 0; }
	return 1; }


static int
client_loop(struct client_options *opt) {
	int fd;
	struct ddns_message msg;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (!fd) {
		log_c_socket();
		return 0; }

	if (!connect_socket(fd, opt)) return 0;

	msg.time = time(0);
	msg.name = opt->name->data;
	msg.namelen = opt->name->size;
	msg.addr[0] = msg.addr[1] = msg.addr[2] = msg.addr[3] = 0;

	if (opt->interval <= 0)
		return send_message(fd, &msg, opt->key);

	for (;;) {
		msg.time = time(0);
		if (!send_message(fd, &msg, opt->key)) return 0;
		sleep(opt->interval); }

	return 1; }


int
main(void) {
	struct sexp *arg;
	struct client_options opt = DEFAULT_OPT;

	arg = sxp_read(stdin, 1024);
	if (!arg) {
		log_c_no_options();
		return EXIT_FAILURE; }

	if (!parse_options(&opt, arg)
	|| !client_loop(&opt))
		 return EXIT_FAILURE;

	return 0; }

/* vim: set filetype=c: */
