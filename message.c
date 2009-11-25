/* message.c - function handling ddns messages */

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

#include "message.h"

#include "sha1.h"

#include <string.h>



/*************************
 * DATE HELPER FUNCTIONS *
 *************************/

static size_t
decode_time(time_t *out, const unsigned char *buf, size_t buflen) {
	time_t r = 0;
	unsigned i = 0;

	while (i < buflen && buf[i] >= '0' && buf[i] <= '9') {
		r = (r * 10) + buf[i] - '0';
		i += 1; }
	if (i >= buflen || buf[i] != 0) return 0;
	*out = r;
	return i + 1; }


static size_t
encode_time(unsigned char *buf, size_t buflen, time_t date) {
	unsigned i = 0, j;
	unsigned char c;

	while (i < buflen && date > 0) {
		buf[i] = '0' + date % 10;
		date /= 10;
		i += 1; }
	if (i >= buflen) return 0;
	buf[i] = 0;
	for (j = 0; j < i - 1 - j; j += 1) {
		c = buf[i - 1 - j];
		buf[i - 1 - j] = buf[j];
		buf[j] = c; }
	return i + 1; }



/*************************
 * NAME HELPER FUNCTIONS *
 *************************/

static size_t
decode_name(const char **pname, size_t *pnamelen,
				const unsigned char *buf, size_t buflen) {
	unsigned i = 0;
	while (i < buflen && buf[i] != 0) i += 1;
	if (i >= buflen) return 0;
	*pname = (const char *)buf;
	*pnamelen = i;
	return i + 1; }


static size_t
encode_name(unsigned char *buf, size_t buflen,
					const void *name, size_t namelen) {
	if (namelen + 1 >= buflen) return 0;
	memcpy(buf, name, namelen);
	buf[namelen] = 0;
	return namelen + 1; }



/****************************
 * ADDRESS HELPER FUNCTIONS *
 ****************************/

static size_t
decode_addr(unsigned char out[4], const unsigned char *buf, size_t buflen) {
	if (buflen < 5 || buf[4] != 0) return 0;
	out[0] = buf[0];
	out[1] = buf[1];
	out[2] = buf[2];
	out[3] = buf[3];
	return 5; }


static size_t
encode_addr(unsigned char *buf, size_t buflen, unsigned char addr[4]) {
	if (buflen < 5) return 0;
	buf[0] = addr[0];
	buf[1] = addr[1];
	buf[2] = addr[2];
	buf[3] = addr[3];
	buf[4] = 0;
	return 5; }



/*************************
 * HMAC HELPER FUNCTIONS *
 *************************/

static size_t
decode_hmac(unsigned char *out, const unsigned char *buf, size_t buflen) {
	if (buflen < HMAC_SIZE + sizeof HMAC_NAME - 1
	|| strncmp((const char *)buf + HMAC_SIZE,
					HMAC_NAME, sizeof HMAC_NAME - 1))
		return 0;
	memcpy(out, buf, HMAC_SIZE);
	return HMAC_SIZE + sizeof HMAC_NAME - 1; }


static size_t
encode_hmac(unsigned char *buf, size_t buflen, unsigned char *hmac) {
	if (buflen < HMAC_SIZE + sizeof HMAC_NAME - 1) return 0;
	memcpy(buf, hmac, HMAC_SIZE);
	memcpy(buf + HMAC_SIZE, HMAC_NAME, sizeof HMAC_NAME - 1);
	return HMAC_SIZE + sizeof HMAC_NAME - 1; }



/**********************
 * EXPORTED FUNCTIONS *
 **********************/

/* decode_message • fills a ddns_message struture from the given buffer
 *	returns the acutal size of the message or 0 on error */
size_t
decode_message(struct ddns_message *msg, const void *buf, size_t buflen) {
	const unsigned char *ubuf = buf;
	size_t i = 0, r;
	r = decode_time(&msg->time, ubuf + i, buflen - i);
	if (!r) return 0; else i += r;
	r = decode_name(&msg->name, &msg->namelen, ubuf + i, buflen - i);
	if (!r) return 0; else i += r;
	r = decode_addr(msg->addr, ubuf + i, buflen - i);
	if (!r) return 0; else i += r;
	r = decode_hmac(msg->hmac, ubuf + i, buflen - i);
	if (!r || i + r != buflen) return 0;
	return i; }


/* encode_message • fills a buffer from the given ddns_message structure
 *	returns the total size of the message or 0 on error */
size_t
encode_message(void *buf, size_t buflen, struct ddns_message *msg,
					const void *key, size_t keylen) {
	unsigned char *ubuf = buf;
	size_t i = 0, r;
	r = encode_time(ubuf + i, buflen - i, msg->time);
	if (!r) return 0; else i += r;
	r = encode_name(ubuf + i, buflen - i, msg->name, msg->namelen);
	if (!r) return 0; else i += r;
	r = encode_addr(ubuf + i, buflen - i, msg->addr);
	if (!r) return 0; else i += r;
	sha1_hmac(msg->hmac, buf, i, key, keylen);
	r = encode_hmac(ubuf + i, buflen - i, msg->hmac);
	if (!r) return 0; else i += r;
	return i; }

/* vim: set filetype=c: */
