/* message.h - function handling ddns messages */

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

#ifndef DDNS_MESSAGE_H
#define DDNS_MESSAGE_H

#include <time.h>


/*************************
 * COMPILE-TIME CONSTANTS *
 *************************/

#define HMAC_NAME	"sha-1"
#define HMAC_SIZE	20
#define MAX_MSG_SIZE	1024



/*******************
 * TYPE DEFINITION *
 *******************/

struct ddns_message {
	time_t		 time;
	const char	*name;
	size_t		 namelen;
	unsigned char	 addr[4];
	unsigned char	 hmac[HMAC_SIZE]; };



/**********************
 * EXPORTED FUNCTIONS *
 **********************/

/* decode_message • fills a ddns_message struture from the given buffer
 *	returns the acutal size of the message (without HMAC) or 0 on error */
size_t
decode_message(struct ddns_message *msg, const void *buf, size_t buflen);


/* encode_message • fills a buffer from the given ddns_message structure
 *	returns the total size of the message (including HMAC) or 0 on error */
size_t
encode_message(void *buf, size_t buflen, struct ddns_message *msg,
					const void *key, size_t keylen);

#endif /* ndef DDNS_MESSAGE_H */

/* vim: set filetype=c: */
