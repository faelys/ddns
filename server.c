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
#include "csexp.h"
#include "log.h"
#include "message.h"
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
	char		*name;
	size_t		 nsize;
	char		*key;
	size_t		 ksize;
	unsigned char	 last_addr[4];
	time_t		 last_seen;
	int		 max_future;
	int		 max_past;
	int		 timeout;
	struct {
		unsigned allow_unsafe:1;
		unsigned active:1;
	}		 flags;
};


/* init_account • initialization of the struct account */
static void
init_account(struct account *acc) {
	acc->name = 0;
	acc->nsize = 0;
	acc->key = 0;
	acc->ksize = 0;
	acc->last_addr[0] = acc->last_addr[1] =
		acc->last_addr[2] = acc->last_addr[3] = 0;
	acc->last_seen = 0;
	acc->max_future = acc->max_past =  acc->timeout = -1;
	acc->flags.active = 0;
	acc->flags.allow_unsafe = 0; }


/* free_account • release of the struct account members */
static void
free_account(struct account *acc) {
	free(acc->name);
	free(acc->key); }


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
	return data_cmp(acc1->name, acc1->nsize,
			acc2->name, acc2->nsize); }


/* cmp_msg_to_acc • comparison function for bsearch()ing the account from msg*/
static int
cmp_msg_to_acc(const void *a, const void *b) {
	const struct ddns_message *msg = a;
	const struct account *acc = b;
	return data_cmp(msg->name, msg->namelen,
			acc->name, acc->nsize); }


/* mkinter • helper function for interval, returns -1 on invalid number */
static int
mkinter(struct sx_node *node) {
	char *end;
	long ret;
	if (!node || !SX_IS_ATOM(node)) return -1;
	ret = strtol(node->data, &end, 10);
	if (*end || ret < 0) return -1;
	return ret; }


/* parse_account • fills a struct account according to a S-expression */
static void
parse_account(struct account *acc, struct sx_node *sx) {
	struct sx_node *s, *t, *arg;
	const char *cmd;
	void *neo;
	for (s = sx; s; s = s->next)
		if (!SX_CHILD(s)
		|| (cmd = SX_DATA(SX_CHILD(s))) == 0
		|| (arg = SX_CHILD(s)->next) == 0)
			continue;
		else if (!strcmp(cmd, "key")) {
			if (!SX_IS_ATOM(arg)) continue;
			neo = realloc(acc->key, arg->size);
			if (!neo) continue;
			acc->key = neo;
			acc->ksize = arg->size;
			memcpy(acc->key, arg->data, arg->size); }
		else if (!strcmp(cmd, "interval")) {
			acc->max_past = mkinter(arg);
			acc->max_future = arg->next ? mkinter(arg->next)
						    : acc->max_past; }
		else if (!strcmp(cmd, "max-future"))
			acc->max_future = mkinter(arg);
		else if (!strcmp(cmd, "max-past"))
			acc->max_past = mkinter(arg);
		else if (!strcmp(cmd, "name")) {
			if (!SX_IS_ATOM(arg)) continue;
			neo = realloc(acc->name, arg->size);
			if (!neo) continue;
			acc->name = neo;
			acc->nsize = arg->size;
			memcpy(acc->name, arg->data, arg->size); }
		else if (!strcmp(cmd, "timeout"))
			acc->timeout = mkinter(arg);
		else if (!strcmp(cmd, "flags")
		|| !strcmp(cmd, "flag")) {
			for (t = arg; t; t = t->next)
				if (!SX_IS_ATOM(t)) continue;
				else if (!strcmp(t->data, "allow-unsafe")
				|| !strcmp(t->data, "allow_unsafe"))
					acc->flags.allow_unsafe = 1;
				else if (!strcmp(t->data, "forbid-unsafe")
				|| !strcmp(t->data, "forbid_unsafe")
				|| !strcmp(t->data, "no-unsafe")
				|| !strcmp(t->data, "no_unsafe"))
					acc->flags.allow_unsafe = 0;
				else log_s_bad_account_flag(t->data); }
		else log_s_bad_account_cmd(cmd); }



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
add_listen_fd(struct array *poll_fds, struct sx_node *sx) {
	const char *port = 0;
	const char *iface = 0;
	int fd, ret;
	struct pollfd *pfd;
	struct addrinfo hints;
	struct addrinfo *res, *rp;

	/* argument decoding */
	if (sx && SX_IS_ATOM(sx)) port = SX_DATA(sx);
	if (sx && sx->next && SX_IS_ATOM(sx->next)) iface = SX_DATA(sx->next);
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


/* reload_options • reloads options from the given file */
/*	returns 0 on success, -1 on failure */
static int
reload_options(struct server_options *opt) {
	struct sexp sx;
	struct sx_node *s;
	struct server_options neo;
	FILE *f;
	time_t mt;
	int i;

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
	i = sxp_file_to_sx(&sx, f, 4096, 4096, 64);
	fclose(f);
	if (i < 0 || !sx.nsize) {
		log_s_empty_config(opt->filename);
		return 0; }

	/* preloading the new options */
	init_server_options(&neo);
	neo.filename = opt->filename;
	neo.mtime = opt->mtime;
	if (opt->fds.size) {
		arr_grow(&neo.fds, opt->fds.size);
		memcpy(neo.fds.base, opt->fds.base,
				opt->fds.size * opt->fds.unit);
		neo.fds.size = opt->fds.size; }

	/* reading S-expression data */
	for (s = sx.nodes; s; s = s->next)
		if (!SX_CHILD(s) || !SX_CHILD(s)->next) continue;
		else if (!strcmp(SX_DATA(SX_CHILD(s)), "listen"))
			add_listen_fd(&neo.fds, SX_CHILD(s)->next);
		else if (!strcmp(SX_DATA(SX_CHILD(s)), "account")) {
			struct account acc, *pacc;
			init_account(&acc);
			parse_account(&acc, SX_CHILD(s)->next);
			if (!acc.name || !acc.nsize
			||  !acc.key  || !acc.ksize) {
				free_account(&acc);
				continue; }
			pacc = arr_item(&neo.accounts,
						arr_newitem(&neo.accounts));
			*pacc = acc; }
		else log_s_bad_cmd(SX_DATA(SX_CHILD(s)));

	/* sanity checks */
	if (!neo.fds.size) {
		log_s_no_listen(opt->filename);
		return 0; }
	else log_s_listen_nb(neo.fds.size);

	/* post-processing */
	qsort(neo.accounts.base, neo.accounts.size, neo.accounts.unit,
			cmp_acc_to_acc);

	/* copying data into the real structure */
	free_server_options(opt);
	*opt = neo;

	/* clean-up */
	sx_release(&sx);
	return 1; }



/*************
 * MAIN LOOP *
 *************/

/* raw_message • structure containing recieved data waiting to be processed */
struct raw_message {
	unsigned char		data[MAX_MSG_SIZE];
	size_t			datalen;
	struct sockaddr_in	peer; };

/* terminated • flag set upon SIGTERM reception */
static int terminated = 0;


/* sig_handler • handling SIGTERM to exit cleanly */
static void
sig_handler(int a) {
	(void)a;
	terminated = 1; }


/* process_message • reads and processes a message from a fd */
static void
process_message(struct server_options *opt, struct raw_message *rmsg) {
	struct ddns_message msg;
	size_t msglen;
	int i;
	unsigned char *real_addr;
	struct account *acc;
	unsigned char hmac[20];
	time_t now;

	/* decoding message */
	msglen = decode_message(&msg, rmsg->data, rmsg->datalen);
	if (!msglen) return;

	/* looking for a matching account */
	acc = bsearch(&msg, opt->accounts.base, opt->accounts.size,
				opt->accounts.unit, cmp_msg_to_acc);
	if (!acc) {
		log_s_no_account(msg.name, msg.namelen);
		return; }

	/* checking hmac */
	sha1_hmac(hmac, rmsg->data, msglen, acc->key, acc->ksize);
	for (i = 0; i < 20; i += 1) if (msg.hmac[i] != hmac[i]) break;
	if (i < 20) {
		log_s_bad_hmac(&msg, hmac);
		return; }

	/* checking peer address against message address */
	real_addr = (unsigned char *)&rmsg->peer.sin_addr.s_addr;
	if (real_addr[0] != msg.addr[0] || real_addr[1] != msg.addr[1]
	||  real_addr[2] != msg.addr[2] || real_addr[3] != msg.addr[3]) {
		/* reject message if message addr != 0.0.0.0 */
		if (msg.addr[0] || msg.addr[1]
		|| msg.addr[2] || msg.addr[3]) {
			log_s_addr_mismatch(&msg, real_addr);
			return; }
		/* check whether unsafe mode is allowed for this account */
		if (!acc->flags.allow_unsafe) {
			log_s_unsafe_forbidden(&msg, real_addr);
			return; }
		/* unsafe mode allowed, copying peer address into msg */
		msg.addr[0] = real_addr[0];
		msg.addr[1] = real_addr[1];
		msg.addr[2] = real_addr[2];
		msg.addr[3] = real_addr[3]; }

	/* checking send time */
	now = time(0);
	i = difftime(now, msg.time);
	if ((acc->max_future > 0 && -i > acc->max_future)
	||  (acc->max_past   > 0 &&  i > acc->max_past)) {
		log_s_bad_time(&msg, i, acc->max_past, acc->max_future);
		return; }

	/* --- The message is accepted --- */

	/* updating last seen time */
	acc->last_seen = now;

	/* check for address change */
	if (msg.addr[0] == acc->last_addr[0] && msg.addr[1] == acc->last_addr[1]
	&& msg.addr[2] == acc->last_addr[2] && msg.addr[3] == acc->last_addr[3])
		return;

	/* marking the account as active */
	if (!acc->flags.active) {
		acc->flags.active = 1;
		log_s_account_up(acc->name, acc->nsize, msg.addr); }
	else log_s_addr_change(acc->name, acc->nsize, acc->last_addr, msg.addr);

	/* copying the new address */
	acc->last_addr[0] = msg.addr[0];
	acc->last_addr[1] = msg.addr[1];
	acc->last_addr[2] = msg.addr[2];
	acc->last_addr[3] = msg.addr[3];

	/* TODO: actual DNS update */ }


/* check_timeout • checks accounts for timeouts, returns the time before next*/
static int
check_timeout(struct server_options *opt) {
	struct account *acc = opt->accounts.base;
	time_t now = time(0);
	int i, dt;
	int ret = -1;

	for (i = 0; i < opt->accounts.size; i += 1) {
		/* skipping accounts that cannot time out */
		if (!acc[i].flags.active
		|| acc[i].timeout <= 0)
			continue;

		/* checking time out */
		if (acc[i].last_seen + acc[i].timeout <= now) {
			log_s_account_down(acc[i].name, acc[i].nsize,
							acc[i].last_addr);
			acc[i].flags.active = 0;
			acc[i].last_addr[0] = acc[i].last_addr[1] = 
				acc[i].last_addr[2] = acc[i].last_addr[3] = 0;
			/* TODO: actual DNS update */
			continue; }

		/* computing next timeout */
		dt = (acc[i].last_seen + acc[i].timeout - now) * 1000;
		if (ret < 0 || ret > dt) ret = dt; }

	return ret; }


/* main • main program loop */
int
main(int argc, char **argv) {
	int ret, i, timeout;
	struct pollfd *pfd;
	struct server_options opt;
	struct sigaction sa;
	struct array rmsgs;
	struct raw_message *rmsg;
	ssize_t sret;
	socklen_t si_other_len;

	/* arguments checks */
	if (argc < 2) {
		log_s_no_config();
		return EXIT_FAILURE; }

	/* variable initialization */
	arr_init(&rmsgs, sizeof (struct raw_message));
	init_server_options(&opt);
	opt.filename = argv[1];
	if (reload_options(&opt) < 0) {
		log_s_bad_config();
		return EXIT_FAILURE; }

	/* TERM signal catching */
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGTERM, &sa, 0);

	/* poll() loop */
	timeout = -1;
	while ((ret = poll(opt.fds.base, opt.fds.size, timeout)) >= 0
	&& !terminated) {
		/* reading messages */
		pfd = opt.fds.base;
		for (i = 0; i < opt.fds.size; i += 1) {
			if (pfd[i].revents & (POLLHUP | POLLERR))
				log_s_fd_error();
			else if (pfd[i].revents & POLLIN) {
				rmsg = arr_item(&rmsgs, arr_newitem(&rmsgs));
				si_other_len = sizeof rmsg->peer;
				sret = recvfrom(pfd[i].fd, rmsg->data,
					sizeof rmsg->data, MSG_DONTWAIT,
					(struct sockaddr *)&rmsg->peer,
					&si_other_len);
				if (ret < 0) {
					log_s_recvfrom();
					rmsgs.size -= 1; }
				else rmsg->datalen = sret; } }

		/* reloading configuration (if needed) */
		reload_options(&opt);

		/* processing messages */
		rmsg = rmsgs.base;
		for (i = 0; i < rmsgs.size; i += 1)
			process_message(&opt, rmsg + i);
		rmsgs.size = 0;

		/* checking account timeouts */
		timeout = check_timeout(&opt); }

	free_server_options(&opt);
	return EXIT_SUCCESS; }

/* vim: set filetype=c: */
