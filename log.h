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

#include "buffer.h"
#include "message.h"

#include <netdb.h>


/****************************
 * CLIENT LOGGING FUNCTIONS *
 ****************************/

void
log_c_ambiguous_addr(const char *host, const char *port, struct addrinfo *ai);

void
log_c_bad_cmd(struct buf *cmd);

void
log_c_connect(const char *host, const char *port, struct addrinfo *ai);

void
log_c_getaddrinfo(const char *host, const char *port, int errcode);

void
log_c_no_options(void);

void
log_c_send_fail(const void *data, size_t datalen);

void
log_c_send_short(const void *data, size_t datalen, size_t sent);

void
log_c_socket(void);



/**************************
 * MISC LOGGING FUNCTIONS *
 **************************/

void
log_m_message(struct ddns_message *msg, const unsigned char *peer);

void
log_m_stat(const char *filename);



/****************************
 * SERVER LOGGING FUNCTIONS *
 ****************************/

void
log_s_bad_account_cmd(struct buf *cmd);

void
log_s_bad_cmd(struct buf *cmd);

void
log_s_bad_config(void);

void
log_s_bad_hmac(struct ddns_message *msg, unsigned char *real_hmac);

void
log_s_bind(const char *host, const char *port);

void
log_s_getaddrinfo(const char *host, const char *port, int errcode);

void
log_s_empty_config(const char *filename);

void
log_s_fd_error(void);

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
log_s_socket(const char *host, const char *port);


#endif /* ndef DDNS_LOG_H */

/* vim: set filetype=c: */
