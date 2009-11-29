/* server.c - dynamic DNS server */

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

#include "array.h"
#include "log.h"
#include "message.h"
#include "sexp.h"
#include "sha1.h"
#include "utils.h"

#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>


/*******************
 * ACCOUNT OPTIONS *
 *******************/

struct account {
	struct buf	*name;
	struct buf	*key;
};


/* init_account • initialization of the struct account */
static void
init_account(struct account *acc) {
	acc->name = 0;
	acc->key = 0; }


/* free_account • release of the struct account members */
static void
free_account(struct account *acc) {
	bufrelease(acc->name);
	bufrelease(acc->key); }


/* data_cmp • comparison function checking size first, then contents */
static int
data_cmp(const char *data1, size_t len1, const char *data2, size_t len2) {
	int slen1 = len1, slen2 = len2;
	if (slen1 != slen2) return slen1 - slen2;
	else return strncasecmp(data1, data2, len1); }


/* cmp_acc_to_acc • comparison function for qsort()ing a struct account array*/
static int
cmp_acc_to_acc(const void *a, const void *b) {
	const struct account *acc1 = a;
	const struct account *acc2 = b;
	return data_cmp(acc1->name->data, acc1->name->size,
			acc2->name->data, acc2->name->size); }


/* cmp_msg_to_acc • comparison function for bsearch()ing the account from msg*/
static int
cmp_msg_to_acc(const void *a, const void *b) {
	const struct ddns_message *msg = a;
	const struct account *acc = b;
	return data_cmp(msg->name, msg->namelen,
			acc->name->data, acc->name->size); }


/* parse_account • fills a struct account according to a S-expression */
static void
parse_account(struct account *acc, struct sexp *sx) {
	struct sexp *s;
	for (s = sx; s; s = s->next)
		if (!s->list || !s->list->node) continue;
		else if (!bufcmps(s->list->node, "name")) {
			if (s->list->next)
				bufset(&acc->name, s->list->next->node); }
		else if (!bufcmps(s->list->node, "key")) {
			if (s->list->next)
				bufset(&acc->key, s->list->next->node); }
		else log_s_bad_account_cmd(s->list->node); }



/******************
 * SERVER OPTIONS *
 ******************/

/* server_options • structure containing global server settings */
struct server_options {
	const char	*filename;
	time_t		 mtime;
	struct array	 accounts;
	struct array	 fds;
};


/* init_server_options • initialization of struct server_options */
static void
init_server_options(struct server_options *opt) {
	opt->filename = 0;
	opt->mtime = 0;
	arr_init(&opt->accounts, sizeof (struct account));
	arr_init(&opt->fds, sizeof (struct pollfd)); }


/* free_server_options • release of struct server_options members */
static void
free_server_options(struct server_options *opt) {
	int i;
	struct account *acc = opt->accounts.base;
	for (i = 0; i < opt->accounts.size; i += 1)
		free_account(acc + i);
	arr_free(&opt->accounts);
	arr_free(&opt->fds); }


/* add_listen_fd • creates the described by the S-exp and adds it to poll_fds*/
static void
add_listen_fd(struct array *poll_fds, struct sexp *sx) {
	const char *port = 0;
	const char *iface = 0;
	int fd, ret;
	struct pollfd *pfd;
	struct addrinfo hints;
	struct addrinfo *res, *rp;

	/* argument decoding */
	if (sx && sx->node) {
		bufnullterm(sx->node);
		port = sx->node->data; }
	if (sx && sx->next && sx->next->node) {
		bufnullterm(sx->next->node);
		iface = sx->next->node->data; }
	if (!port) return;

	/* address look-up */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	ret = getaddrinfo(iface, port, &hints, &res);
	if (ret) {
		log_s_getaddrinfo(iface, port, ret);
		return; }

	/* iterating over results */
	for (rp = res; rp; rp = rp->ai_next) {
		/* socket creation */
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd < 0) {
			log_s_socket(iface, port);
			continue; }

		/* socket binding */
		if (bind(fd, rp->ai_addr, rp->ai_addrlen)) {
			log_s_bind(iface, port);
			continue; }

		/* addition of the socket to the pollfd array */
		pfd = arr_item(poll_fds, arr_newitem(poll_fds));
		pfd->fd = fd;
		pfd->events = POLLIN; }

	/* clean-up */
	freeaddrinfo(res); }


/* reload_options • reloads options from the given file, returns zero on fail*/
static int
reload_options(struct server_options *opt) {
	struct sexp *sx, *s;
	struct server_options neo;
	FILE *f;
	time_t mt;

	/* checking whether the file has changed */
	mt = get_mtime(opt->filename);
	if (!mt) return 0;
	if (mt == opt->mtime) return 1;
	opt->mtime = mt;

	/* loading the file */
	f = fopen(opt->filename, "rb");
	if (!f) {
		log_s_open_config(opt->filename);
		return 0; }
	sx = sxp_read(f, 4096);
	fclose(f);
	if (!sx) {
		log_s_empty_config(opt->filename);
		return 0; }

	/* reading S-expression data */
	init_server_options(&neo);
	neo.filename = opt->filename;
	neo.mtime = opt->mtime;
	for (s = sx; s; s = s->next)
		if (!s->list || !s->list->node) continue;
		else if (!bufcmps(s->list->node, "listen"))
			add_listen_fd(&neo.fds, s->list->next);
		else if (!bufcmps(s->list->node, "account")) {
			struct account acc, *pacc;
			init_account(&acc);
			parse_account(&acc, s->list->next);
			if (!acc.name || !acc.name->size
			||  !acc.key  || !acc.key->size) {
				free_account(&acc);
				continue; }
			pacc = arr_item(&neo.accounts,
						arr_newitem(&neo.accounts));
			*pacc = acc; }
		else log_s_bad_cmd(s->list->node);

	/* sanity checks */
	if (!neo.fds.size) {
		log_s_no_listen(opt->filename);
		return 0; }

	/* post-processing */
	qsort(neo.accounts.base, neo.accounts.size, neo.accounts.unit,
			cmp_acc_to_acc);

	/* copying data into the real structure */
	free_server_options(opt);
	*opt = neo;

	/* clean-up */
	sx_free(sx);
	return 1; }



/*************
 * MAIN LOOP *
 *************/

/* terminated • flag set upon SIGTERM reception */
static int terminated = 0;


/* sig_handler • handling SIGTERM to exit cleanly */
static void
sig_handler(int a) {
	terminated = 1; }


/* read_message • reads and processes a message from a fd */
static void
read_message(int fd, struct server_options *opt) {
	unsigned char data[MAX_MSG_SIZE];
	ssize_t ret;
	struct sockaddr_in si_other;
	socklen_t si_other_len = sizeof si_other;
	struct ddns_message msg;
	size_t msglen;
	int i;
	unsigned char *real_addr;
	struct account *acc;
	unsigned char hmac[20];

	/* reads the message from the fd */
	ret = recvfrom(fd, data, sizeof data, MSG_DONTWAIT,
				(struct sockaddr *)&si_other, &si_other_len);
	if (ret < 0) {
		log_s_recvfrom();
		return; }

	/* decoding message */
	msglen = decode_message(&msg, data, ret);
	if (!msglen) return;

	/* looking for a matching account */
	acc = bsearch(&msg, opt->accounts.base, opt->accounts.size,
				opt->accounts.unit, cmp_msg_to_acc);
	if (!acc) {
		log_s_no_account(msg.name, msg.namelen);
		return; }

	/* checking hmac */
	sha1_hmac(hmac, data, msglen, acc->key->data, acc->key->size);
	for (i = 0; i < 20; i += 1) if (msg.hmac[i] != hmac[i]) break;
	if (i < 20) {
		log_s_bad_hmac(&msg, hmac);
		return; }

	/* message dump */
	real_addr = (unsigned char *)&si_other.sin_addr.s_addr;
	log_m_message(&msg, real_addr); }


/* main • main program loop */
int
main(int argc, char **argv) {
	int ret, i;
	struct pollfd *pfd;
	struct server_options opt;
	struct sigaction sa;

	/* arguments checks */
	if (argc < 2) {
		log_s_no_config();
		return EXIT_FAILURE; }

	/* variable initialization */
	init_server_options(&opt);
	opt.filename = argv[1];
	if (!reload_options(&opt)) {
		log_s_bad_config();
		return EXIT_FAILURE; }

	/* TERM signal catching */
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGTERM, &sa, 0);

	/* poll() loop */
	while ((ret = poll(opt.fds.base, opt.fds.size, -1)) >= 0
	&& !terminated) {
		/* iterating over fd */
		pfd = opt.fds.base;
		for (i = 0; i < opt.fds.size; i += 1) {
			if (pfd[i].revents & POLLIN)
				read_message(pfd[i].fd, &opt);
			if (pfd[i].revents & (POLLHUP | POLLERR))
				log_s_fd_error();  } }

	free_server_options(&opt);
	return EXIT_SUCCESS; }

/* vim: set filetype=c: */
