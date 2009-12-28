/* log.h - logging functions */

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

#ifndef DDNS_LOG_H
#define DDNS_LOG_H

#include "message.h"

#include <netdb.h>


/**************************
 * LOG MANAGING FUNCTIONS *
 **************************/

void
log_open(const char *name);

void
log_close(void);



/****************************
 * CLIENT LOGGING FUNCTIONS *
 ****************************/

void
log_c_ambiguous_addr(const char *host, const char *port, struct addrinfo *ai);

void
log_c_bad_cmd(const char *cmd);

void
log_c_bad_sensor(const char *cmd);

void
log_c_connect(const char *host, const char *port, struct addrinfo *ai);

void
log_c_exiting(void);

void
log_c_getaddrinfo(const char *host, const char *port, int errcode);

void
log_c_no_options(void);

void
log_c_open_conf(const char *filename);

void
log_c_pipe_bad_addr(const char *buf, size_t size);

void
log_c_pipe_error(const char *cmd);

void
log_c_pipe_read_error(const char *cmd);

void
log_c_send_fail(const void *data, size_t datalen);

void
log_c_send_short(const void *data, size_t datalen, size_t sent);

void
log_c_short_buf(void);

void
log_c_socket(void);



/**************************
 * MISC LOGGING FUNCTIONS *
 **************************/

void
log_m_bad_user(const char *user);

void
log_m_chdir(const char *root);

void
log_m_chroot(const char *root);

void
log_m_daemon(void);

void
log_m_fork(void);

void
log_m_message(struct ddns_message *msg, const unsigned char *peer);

void
log_m_pid_create(const char *filename);

void
log_m_pid_exist(const char *filename, long pid);

void
log_m_pid_invalid(const char *filename);

void
log_m_pid_kill(const char *filename, long pid);

void
log_m_pid_open(const char *filename);

void
log_m_pid_trunc(const char *filename);

void
log_m_setgid(const char *user);

void
log_m_setuid(const char *user);

void
log_m_setsid(void);

void
log_m_stat(const char *filename);



/****************************
 * SERVER LOGGING FUNCTIONS *
 ****************************/

void
log_s_account_down(const char *name, size_t nsize,
					const unsigned char *last_addr);

void
log_s_account_up(const char *name, size_t nsize, const unsigned char *addr);

void
log_s_addr_change(const char *name, size_t nsize, const unsigned char *old_addr,
					const unsigned char *new_addr);

void
log_s_addr_mismatch(struct ddns_message *msg, const unsigned char *peer);

void
log_s_bad_account_cmd(const char *cmd);

void
log_s_bad_account_flag(const char *flag);

void
log_s_bad_cmd(const char *cmd);

void
log_s_bad_config(void);

void
log_s_bad_effector(const char *cmd);

void
log_s_bad_hmac(struct ddns_message *msg, unsigned char *real_hmac);

void
log_s_bad_time(struct ddns_message *msg, int dt, int past, int future);

void
log_s_bind(const char *host, const char *port);

void
log_s_effkill_bad_signal(const char *signal, const char *pidfile);

void
log_s_effkill_open(const char *pidfile);

void
log_s_effkill_bad_pidfile(const char *pidfile);

void
log_s_effkill_kill(int pid, const char *pidfile, long sig, const char *signal);

void
log_s_exiting(void);

void
log_s_getaddrinfo(const char *host, const char *port, int errcode);

void
log_s_empty_config(const char *filename);

void
log_s_fd_error(void);

void
log_s_hmac_decode_error(const unsigned char *buf, size_t buflen);

void
log_s_inval_time(const unsigned char *buf, size_t buflen);

void
log_s_listen_nb(int nb);

void
log_s_no_account(const char *name, size_t namelen);

void
log_s_no_config(void);

void
log_s_no_listen(const char *filename);

void
log_s_open_config(const char *filename);

void
log_s_recvfrom(void);

void
log_s_short_addr(const unsigned char *buf, size_t buflen);

void
log_s_short_name(const unsigned char *buf, size_t buflen);

void
log_s_short_time(const unsigned char *buf, size_t buflen);

void
log_s_socket(const char *host, const char *port);

void
log_s_system(const char *cmd);

void
log_s_system_alloc(size_t sz);

void
log_s_system_error(const char *cmd, int status);

void
log_s_unsafe_forbidden(struct ddns_message *msg, const unsigned char *peer);

void
log_s_zone_future_serial(const char *serial, const char *filename);

void
log_s_zone_no_serial(const char *filename);

void
log_s_zone_open_r(const char *filename);

void
log_s_zone_open_w(const char *filename);

void
log_s_zone_realloc(const char *filename, size_t asize);

void
log_s_zone_short_write(const char *filename, size_t written, size_t size);

void
log_s_zone_update(const char *filename, const char *name, size_t nsize,
					unsigned char addr[4]);

#endif /* ndef DDNS_LOG_H */

/* vim: set filetype=c: */
