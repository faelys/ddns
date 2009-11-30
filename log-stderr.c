/* log-stderr.c - logging functions, writing into stderr */

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

#include <errno.h>
#include <stdio.h>
#include <string.h>


/****************************
 * CLIENT LOGGING FUNCTIONS *
 ****************************/

void
log_c_ambiguous_addr(const char *host, const char *port, struct addrinfo *ai) {
	fprintf(stderr, "Ambiguous address for %s:%s\n", host, port);
	do {
		fprintf(stderr, "   %s\n", ai->ai_canonname);
		ai = ai->ai_next;
	} while (ai); }


void
log_c_bad_cmd(struct buf *cmd) {
	fprintf(stderr, "Unknown client option \"%.*s\"\n",
						(int)cmd->size, cmd->data); }


void
log_c_connect(const char *host, const char *port, struct addrinfo *ai) {
	fprintf(stderr, "Unable to connect() to %s:%s (%s): %s\n",
			host, port, ai->ai_canonname, strerror(errno)); }


void
log_c_getaddrinfo(const char *host, const char *port, int errcode) {
	fprintf(stderr, "Address lookup of %s:%s failed: %s\n",
		host ? host : "*", port ? port : "*", gai_strerror(errcode)); }


void
log_c_no_options(void) { }


void
log_c_send_fail(const void *data, size_t datalen) {
	fprintf(stderr, "Send failure of message: %s\n", strerror(errno)); }


void
log_c_send_short(const void *data, size_t datalen, size_t sent) {
	fprintf(stderr, "Short send of message (%zu/%zu)\n", sent, datalen); }


void
log_c_socket(void) {
	fprintf(stderr, "Unable to create socket: %s\n", strerror(errno)); }



/**************************
 * MISC LOGGING FUNCTIONS *
 **************************/

void
log_m_message(struct ddns_message *msg, const unsigned char *peer) {
	if (peer)
		fprintf(stderr, "Message from %u.%u.%u.%u",
			peer[0], peer[1], peer[2], peer[3]);
	else fprintf(stderr, "Message");
	if (msg->time)
		fprintf(stderr, " at %ld (%+g)",
				(long)msg->time, difftime(time(0), msg->time));
	fprintf(stderr, "\n   ");
	if (msg->name && msg->namelen)
		fprintf(stderr, " name \"%.*s\"", (int)msg->namelen,msg->name);
	fprintf(stderr, " address %u.%u.%u.%u\n",
		msg->addr[0], msg->addr[1], msg->addr[2], msg->addr[3]); }

void
log_m_stat(const char *filename) {
	fprintf(stderr, "Unable to stat \"%s\": %s\n",
						filename, strerror(errno)); }



/****************************
 * SERVER LOGGING FUNCTIONS *
 ****************************/

void
log_s_bad_account_cmd(struct buf *cmd) {
	fprintf(stderr, "Unknown account option \"%.*s\"\n",
						(int)cmd->size, cmd->data); }

void
log_s_bad_cmd(struct buf *cmd) {
	fprintf(stderr, "Unknown server option \"%.*s\"\n",
						(int)cmd->size, cmd->data); }

void
log_s_bad_config(void) {
	fprintf(stderr, "Bad starting config, exiting\n"); }

void
log_s_bad_hmac(struct ddns_message *msg, unsigned char *real_hmac) {
	fprintf(stderr, "HMAC mismatch\n"); }

void
log_s_bind(const char *host, const char *port) {
	fprintf(stderr, "Unable to bind stocket to %s:%s: %s\n",
		host ? host : "*", port ? port : "*", strerror(errno)); }

void
log_s_getaddrinfo(const char *host, const char *port, int errcode) {
	fprintf(stderr, "Address lookup of %s:%s failed: %s\n",
		host ? host : "*", port ? port : "*", gai_strerror(errcode)); }

void
log_s_empty_config(const char *filename) {
	fprintf(stderr, "Empty configuration file \"%s\"\n", filename); }

void
log_s_fd_error(void) {
	fprintf(stderr, "Polled socket is in an error state\n"); }

void
log_s_no_account(const char *name, size_t namelen) {
	fprintf(stderr, "Account \"%.*s\" not found.\n", (int)namelen, name); }

void
log_s_no_config(void) {
	fprintf(stderr, "No configuration file provided in invokation\n"); }

void
log_s_no_listen(const char *filename) {
	fprintf(stderr, "No valid listening socket from \"%s\"\n", filename); }

void
log_s_open_config(const char *filename) {
	fprintf(stderr, "Unable to open configuration file \"%s\": %s\n",
				filename, strerror(errno)); }

void
log_s_recvfrom(void) {
	fprintf(stderr, "recvfrom failure: %s\n", strerror(errno)); }

void
log_s_socket(const char *host, const char *port) {
	fprintf(stderr, "Unable to create socket for %s:%s: %s\n",
		host ? host : "*", port ? port : "*", strerror(errno)); }

/* vim: set filetype=c: */