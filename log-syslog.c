/* log-syslog.c - logging functions, writing into syslog */

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
#include <string.h>
#include <syslog.h>
#include <unistd.h>


/**************************
 * LOG MANAGING FUNCTIONS *
 **************************/

void
log_open(const char *name) {
	openlog(name, LOG_PID, LOG_DAEMON); }

void
log_close(void) {
	closelog(); }



/****************************
 * CLIENT LOGGING FUNCTIONS *
 ****************************/

void
log_c_ambiguous_addr(const char *host, const char *port, struct addrinfo *ai) {
	syslog(LOG_ERR, "Ambiguous address for %s:%s\n", host, port);
	do {
		syslog(LOG_ERR, "   %s\n", ai->ai_canonname);
		ai = ai->ai_next;
	} while (ai); }


void
log_c_bad_cmd(const char *cmd) {
	syslog(LOG_WARNING, "Unknown client option \"%s\"\n", cmd); }


void
log_c_bad_sensor(const char *cmd) {
	syslog(LOG_WARNING, "Unknown address sensor \"%s\"\n", cmd); }


void
log_c_connect(const char *host, const char *port, struct addrinfo *ai) {
	syslog(LOG_ERR, "Unable to connect() to %s:%s (%s): %s\n",
			host, port, ai->ai_canonname, strerror(errno)); }

void
log_c_exiting(void) {
	syslog(LOG_INFO, "Client exiting\n"); }


void
log_c_getaddrinfo(const char *host, const char *port, int errcode) {
	syslog(LOG_ERR, "Address lookup of %s:%s failed: %s\n",
		host ? host : "*", port ? port : "*", gai_strerror(errcode)); }


void
log_c_no_options(void) { }


void
log_c_open_conf(const char *filename) {
	syslog(LOG_ERR, "Unable to open configuration file \"%s\": %s\n",
				filename, strerror(errno)); }


void
log_c_pipe_bad_addr(const char *buf, size_t size) {
	syslog(LOG_ERR, "Bad pipe sesnsor output: \"%.*s\"\n",
							(int)size, buf); }

void
log_c_pipe_error(const char *cmd) {
	syslog(LOG_ERR, "Error while popen()ing \"%s\"\n", cmd); }


void
log_c_pipe_read_error(const char *cmd) {
	syslog(LOG_ERR, "Error while reading output of \"%s\"\n", cmd); }


void
log_c_send_fail(const void *data, size_t datalen) {
	(void)data;
	(void)datalen;
	syslog(LOG_ERR, "Send failure of message: %s\n", strerror(errno)); }


void
log_c_send_short(const void *data, size_t datalen, size_t sent) {
	(void)data;
	syslog(LOG_ERR, "Short send of message (%zu/%zu)\n", sent, datalen); }


void
log_c_short_buf(void) {
	syslog(LOG_ERR, "Message buffer too short\n"); }


void
log_c_socket(void) {
	syslog(LOG_ERR, "Unable to create socket: %s\n", strerror(errno)); }



/**************************
 * MISC LOGGING FUNCTIONS *
 **************************/

void
log_m_bad_user(const char *user) {
	syslog(LOG_ERR, "Unable to get information about user \"%s\"\n",user);}

void
log_m_chdir(const char *root) {
	(void)root;
	syslog(LOG_ERR, "Unable to chdir: %s\n", strerror(errno)); }

void
log_m_chroot(const char *root) {
	syslog(LOG_ERR, "Unable to chroot(%s); %s\n", root, strerror(errno)); }

void
log_m_daemon(void) {
	syslog(LOG_INFO, "Process successfully daemonized [%ld]\n",
						(long)getpid()); }

void
log_m_fork(void) {
	syslog(LOG_ERR, "Unable to fork(): %s\n", strerror(errno)); }

void
log_m_message(struct ddns_message *msg, const unsigned char *peer) {
	if (peer) {
		if (msg->time)
			syslog(LOG_INFO,"Message from %u.%u.%u.%u at %ld (%+g)",
					peer[0], peer[1], peer[2], peer[3],
					(long)msg->time,
					difftime(time(0), msg->time));
		else	syslog(LOG_INFO, "Message from %u.%u.%u.%u",
					peer[0], peer[1], peer[2], peer[3]); }
	else {
		if (msg->time)
			syslog(LOG_INFO, "Message at %ld (%+g)",
					(long)msg->time,
					difftime(time(0), msg->time));
		else	syslog(LOG_INFO, "Message"); }
	if (msg->name && msg->namelen)
		syslog(LOG_INFO, "    name \"%.*s\" address %u.%u.%u.%u\n",
				(int)msg->namelen,msg->name,
				msg->addr[0], msg->addr[1],
				msg->addr[2], msg->addr[3]);
	else
		syslog(LOG_INFO, " address %u.%u.%u.%u\n",
				msg->addr[0], msg->addr[1],
				msg->addr[2], msg->addr[3]); }

void
log_m_pid_create(const char *filename) {
	syslog(LOG_ERR, "Unable to create PID file \"%s\": %s\n",
				filename, strerror(errno)); }

void
log_m_pid_exist(const char *filename, long pid) {
	syslog(LOG_ERR, "Error: PID file \"%s\" exists and is owned by %ld\n",
				filename, pid); }

void
log_m_pid_invalid(const char *filename) {
	syslog(LOG_ERR, "Invalid PID in existing PID file \"%s\"\n",filename);}

void
log_m_pid_kill(const char *filename, long pid) {
	syslog(LOG_ERR, "kill(%ld, 0) from \"%s\" failure: %s\n",
				pid, filename, strerror(errno)); }

void
log_m_pid_open(const char *filename) {
	syslog(LOG_ERR, "Unable to open existing PID file \"%s\": %s\n",
				filename, strerror(errno)); }

void
log_m_pid_trunc(const char *filename) {
	syslog(LOG_ERR, "Unable to truncate existing PID file \"%s\": %s\n",
				filename, strerror(errno)); }

void
log_m_setgid(const char *user) {
	syslog(LOG_ERR, "Unable to setgid(%s): %s\n", user, strerror(errno)); }

void
log_m_setuid(const char *user) {
	syslog(LOG_ERR, "Unable to setuid(%s): %s\n", user, strerror(errno)); }

void
log_m_setsid(void) {
	syslog(LOG_ERR, "Unable to setsid(): %s\n", strerror(errno)); }

void
log_m_stat(const char *filename) {
	syslog(LOG_ERR, "Unable to stat \"%s\": %s\n",
						filename, strerror(errno)); }



/****************************
 * SERVER LOGGING FUNCTIONS *
 ****************************/

void
log_s_account_down(const char *name, size_t nsize,
					const unsigned char *last_addr) {
	syslog(LOG_INFO, "Account %.*s timeout (last seen at %u.%u.%u.%u)\n",
		(int)nsize, name,
		last_addr[0], last_addr[1], last_addr[2], last_addr[3]); }

void
log_s_account_up(const char *name, size_t nsize, const unsigned char *addr) {
	syslog(LOG_INFO, "Account %.*s up (%u.%u.%u.%u)\n",
			(int)nsize, name,
			addr[0], addr[1], addr[2], addr[3]); }

void
log_s_addr_change(const char *name, size_t nsize, const unsigned char *old_addr,
					const unsigned char *new_addr) {
	syslog(LOG_INFO, "Accound %.*s changed address "
			"from %u.%u.%u.%u to %u.%u.%u.%u\n",
		(int)nsize, name,
		old_addr[0], old_addr[1], old_addr[2], old_addr[3],
		new_addr[0], new_addr[1], new_addr[2], new_addr[3]); }

void
log_s_addr_mismatch(struct ddns_message *msg, const unsigned char *peer) {
	syslog(LOG_WARNING, "Address mismatch between peer %u.%u.%u.%u "
			"and message %u.%u.%u.%u\n",
		peer[0], peer[1], peer[2], peer[3],
		msg->addr[0], msg->addr[1], msg->addr[2], msg->addr[3]); }

void
log_s_bad_account_cmd(const char *cmd) {
	syslog(LOG_WARNING, "Unknown account option \"%s\"\n", cmd); }

void
log_s_bad_account_flag(const char *flag) {
	syslog(LOG_WARNING, "Unknown account flag \"%s\"\n",flag); }

void
log_s_bad_cmd(const char *cmd) {
	syslog(LOG_WARNING, "Unknown server option \"%s\"\n", cmd); }

void
log_s_bad_config(void) {
	syslog(LOG_ERR, "Bad starting config, exiting\n"); }

void
log_s_bad_effector(const char *cmd) {
	syslog(LOG_WARNING, "Unkown server effector \"%s\"\n", cmd); }

void
log_s_bad_hmac(struct ddns_message *msg, unsigned char *real_hmac) {
	(void)msg;
	(void)real_hmac;
	syslog(LOG_WARNING, "HMAC mismatch\n"); }

void
log_s_bad_time(struct ddns_message *msg, int dt, int past, int future) {
	syslog(LOG_WARNING, "Anachronic message %d vs %d,%d\n", dt, past, future);
	log_m_message(msg, 0); }

void
log_s_bind(const char *host, const char *port) {
	syslog(LOG_ERR, "Unable to bind stocket to %s:%s: %s\n",
		host ? host : "*", port ? port : "*", strerror(errno)); }

void
log_s_effkill_bad_signal(const char *signal, const char *pidfile) {
	(void)pidfile;
	syslog(LOG_ERR, "Unkown signal \"%s\"\n", signal); }

void
log_s_effkill_open(const char *pidfile) {
	syslog(LOG_ERR, "Unable to open target PID file \"%s\": %s\n",
				pidfile, strerror(errno)); }

void
log_s_effkill_bad_pidfile(const char *pidfile) {
	syslog(LOG_ERR, "Invalid PID file contents in \"%s\"\n", pidfile); }

void
log_s_effkill_kill(int pid, const char *pidfile, long sig, const char *signal){
	syslog(LOG_ERR, "kill(%d \"%s\", %ld \"%s\") failure: %s\n",
		pid, pidfile, sig, signal, strerror(errno)); }

void
log_s_exiting(void) {
	syslog(LOG_INFO, "Server exiting\n"); }

void
log_s_getaddrinfo(const char *host, const char *port, int errcode) {
	syslog(LOG_ERR, "Address lookup of %s:%s failed: %s\n",
		host ? host : "*", port ? port : "*", gai_strerror(errcode)); }

void
log_s_empty_config(const char *filename) {
	syslog(LOG_ERR, "Empty configuration file \"%s\"\n", filename); }

void
log_s_fd_error(void) {
	syslog(LOG_ERR, "Polled socket is in an error state\n"); }

void
log_s_hmac_decode_error(const unsigned char *buf, size_t buflen) {
	(void)buf;
	(void)buflen;
	syslog(LOG_WARNING, "HMAC decoding error\n"); }

void
log_s_inval_time(const unsigned char *buf, size_t buflen) {
	(void)buf;
	(void)buflen;
	syslog(LOG_WARNING, "Invalid packet\n"); }

void
log_s_listen_nb(int nb) {
	syslog(LOG_INFO, "Listening on %d sockets\n", nb); }

void
log_s_no_account(const char *name, size_t namelen) {
	syslog(LOG_ERR, "Account \"%.*s\" not found.\n", (int)namelen, name); }

void
log_s_no_config(void) {
	syslog(LOG_ERR, "No configuration file provided in invokation\n"); }

void
log_s_no_listen(const char *filename) {
	syslog(LOG_ERR, "No valid listening socket from \"%s\"\n", filename); }

void
log_s_open_config(const char *filename) {
	syslog(LOG_ERR, "Unable to open configuration file \"%s\": %s\n",
				filename, strerror(errno)); }

void
log_s_recvfrom(void) {
	syslog(LOG_ERR, "recvfrom failure: %s\n", strerror(errno)); }

void
log_s_short_addr(const unsigned char *buf, size_t buflen) {
	(void)buf;
	(void)buflen;
	syslog(LOG_WARNING, "Message too short (packet truncated?)\n"); }

void
log_s_short_name(const unsigned char *buf, size_t buflen) {
	(void)buf;
	(void)buflen;
	syslog(LOG_WARNING, "Message too short (packet truncated?)\n"); }

void
log_s_short_time(const unsigned char *buf, size_t buflen) {
	(void)buf;
	(void)buflen;
	syslog(LOG_WARNING, "Message too short (packet truncated?)\n"); }

void
log_s_socket(const char *host, const char *port) {
	syslog(LOG_ERR, "Unable to create socket for %s:%s: %s\n",
		host ? host : "*", port ? port : "*", strerror(errno)); }

void
log_s_system(const char *cmd) {
	syslog(LOG_ERR, "system(\"%s\") fail\n", cmd); }

void
log_s_system_alloc(size_t sz) {
	syslog(LOG_ERR, "Unable to allocate %zu bytes for system effector\n",
				sz); }

void
log_s_system_error(const char *cmd, int status) {
	syslog(LOG_ERR, "System effector \"%s\" failure (%d)\n", cmd, status);}

void
log_s_unsafe_forbidden(struct ddns_message *msg, const unsigned char *peer) {
	syslog(LOG_WARNING, "Rejecting unsafe message\n");
	log_m_message(msg, peer); }

void
log_s_zone_future_serial(const char *serial, const char *filename) {
	syslog(LOG_ERR, "Invalid serial \"%.10s\" from zone \"%s\"\n",
				serial, filename); }

void
log_s_zone_no_serial(const char *filename) {
	syslog(LOG_ERR, "Unable to find serial in zone \"%s\"\n", filename); }

void
log_s_zone_open_r(const char *filename) {
	syslog(LOG_ERR, "Unable to read zone file \"%s\"\n", filename); }

void
log_s_zone_open_w(const char *filename) {
	syslog(LOG_ERR, "Unable to write to zone file \"%s\"\n", filename); }

void
log_s_zone_realloc(const char *filename, size_t asize) {
	syslog(LOG_ERR, "Unable to realloc() %zu bytes "
			"while reading zone \"%s\"\n",
			asize, filename); }

void
log_s_zone_short_write(const char *filename, size_t written, size_t size) {
	syslog(LOG_ERR, "Short write to zone file \"%s\" (%zu/%zu)\n",
				filename, written, size); }

void
log_s_zone_update(const char *filename, const char *name, size_t nsize,
					unsigned char addr[4]) {
	syslog(LOG_INFO, "Updating zone \"%s\" record \"%.*s\" to %u.%u.%u.%u\n",
			filename, (int)nsize, name,
			addr[0], addr[1], addr[2], addr[3]); }

/* vim: set filetype=c: */
