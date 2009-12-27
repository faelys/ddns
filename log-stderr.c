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
log_c_bad_cmd(const char *cmd) {
	fprintf(stderr, "Unknown client option \"%s\"\n", cmd); }


void
log_c_bad_sensor(const char *cmd) {
	fprintf(stderr, "Unknown address sensor \"%s\"\n", cmd); }


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
log_c_pipe_bad_addr(const char *buf, size_t size) {
	fprintf(stderr, "Bad pipe sesnsor output: \"%.*s\"\n",
							(int)size, buf); }

void
log_c_pipe_error(const char *cmd) {
	fprintf(stderr, "Error while popen()ing \"%s\"\n", cmd); }


void
log_c_pipe_read_error(const char *cmd) {
	fprintf(stderr, "Error while reading output of \"%s\"\n", cmd); }


void
log_c_send_fail(const void *data, size_t datalen) {
	(void)data;
	(void)datalen;
	fprintf(stderr, "Send failure of message: %s\n", strerror(errno)); }


void
log_c_send_short(const void *data, size_t datalen, size_t sent) {
	(void)data;
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
log_s_account_down(const char *name, size_t nsize,
					const unsigned char *last_addr) {
	fprintf(stderr, "Account %.*s timeout (last seen at %u.%u.%u.%u)\n",
		(int)nsize, name,
		last_addr[0], last_addr[1], last_addr[2], last_addr[3]); }

void
log_s_account_up(const char *name, size_t nsize, const unsigned char *addr) {
	fprintf(stderr, "Account %.*s up (%u.%u.%u.%u)\n",
			(int)nsize, name,
			addr[0], addr[1], addr[2], addr[3]); }

void
log_s_addr_change(const char *name, size_t nsize, const unsigned char *old_addr,
					const unsigned char *new_addr) {
	fprintf(stderr, "Accound %.*s changed address "
			"from %u.%u.%u.%u to %u.%u.%u.%u\n",
		(int)nsize, name,
		old_addr[0], old_addr[1], old_addr[2], old_addr[3],
		new_addr[0], new_addr[1], new_addr[2], new_addr[3]); }

void
log_s_addr_mismatch(struct ddns_message *msg, const unsigned char *peer) {
	fprintf(stderr, "Address mismatch between peer %u.%u.%u.%u "
			"and message %u.%u.%u.%u\n",
		peer[0], peer[1], peer[2], peer[3],
		msg->addr[0], msg->addr[1], msg->addr[2], msg->addr[3]); }

void
log_s_bad_account_cmd(const char *cmd) {
	fprintf(stderr, "Unknown account option \"%s\"\n", cmd); }

void
log_s_bad_account_flag(const char *flag) {
	fprintf(stderr, "Unknown account flag \"%s\"\n",flag); }

void
log_s_bad_cmd(char *cmd) {
	fprintf(stderr, "Unknown server option \"%s\"\n", cmd); }

void
log_s_bad_config(void) {
	fprintf(stderr, "Bad starting config, exiting\n"); }

void
log_s_bad_effector(const char *cmd) {
	fprintf(stderr, "Unkown server effector \"%.*s\"\n", cmd); }

void
log_s_bad_hmac(struct ddns_message *msg, unsigned char *real_hmac) {
	(void)msg;
	(void)real_hmac;
	fprintf(stderr, "HMAC mismatch\n"); }

void
log_s_bad_time(struct ddns_message *msg, int dt, int past, int future) {
	fprintf(stderr, "Anachronic message %d vs %d,%d\n", dt, past, future);
	log_m_message(msg, 0); }

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
log_s_listen_nb(int nb) {
	fprintf(stderr, "Listening on %d sockets\n", nb); }

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

void
log_s_system(const char *cmd) {
	fprintf(stderr, "system(\"%s\") fail\n", cmd); }

void
log_s_system_alloc(size_t sz) {
	fprintf(stderr, "Unable to allocate %zu bytes for system effector\n",
				sz); }

void
log_s_system_error(const char *cmd, int status) {
	fprintf(stderr, "System effector \"%s\" failure (%d)\n", cmd, status);}

void
log_s_unsafe_forbidden(struct ddns_message *msg, const unsigned char *peer) {
	fprintf(stderr, "Rejecting unsafe message\n");
	log_m_message(msg, peer); }

void
log_s_zone_open_r(const char *filename) {
	fprintf(stderr, "Unable to read zone file \"%s\"\n", filename); }

void
log_s_zone_open_w(const char *filename) {
	fprintf(stderr, "Unable to write to zone file \"%s\"\n", filename); }

void
log_s_zone_realloc(const char *filename, size_t asize) {
	fprintf(stderr, "Unable to realloc() %zu bytes "
			"while reading zone \"%s\"\n",
			asize, filename); }

void
log_s_zone_short_write(const char *filename, size_t written, size_t size) {
	fprintf(stderr, "Short write to zone file \"%s\" (%zu/%zu)\n",
				filename, written, size); }

void
log_s_zone_update(const char *filename, const char *name, size_t nsize,
					unsigned char addr[4]) {
	fprintf(stderr, "Updating zone \"%s\" record \"%.*s\" to %u.%u.%u.%u\n",
			filename, (int)nsize, name,
			addr[0], addr[1], addr[2], addr[3]); }

/* vim: set filetype=c: */
