/* sha1.h - SHA-1 cryptographic hash function, RFC 3174 */

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

#ifndef LITHIUM_SHA1_H
#define LITHIUM_SHA1_H

#include <stddef.h>
#include <stdint.h>


/********************
 * TYPE DEFINITIONS *
 ********************/

/* sha1_state • structure storing internal SHA-1 state */
struct sha1_state {
	uint64_t	size; /* in bytes */
	uint32_t	A, B, C, D, E;
	uint32_t	H[5];
	uint32_t	W[80]; };


/****************************
 * EXPORTED BASIC FUNCTIONS *
 ****************************/

/* sha1_init • initialization of the internal state */
void
sha1_init(struct sha1_state *state);


/* sha1_update • adds data to the internal state */
void
sha1_update(struct sha1_state *state, const void *data, size_t size);


/* sha1_finish • ends the hash and fills the output buffer with the value */
void
sha1_finish(struct sha1_state *state, unsigned char output[20]);



/*******************************
 * EXPORTED ADVANCED FUNCTIONS *
 *******************************/

/* sha1_hash • performs a hash on the given complete message */
void
sha1_hash(unsigned char output[20], const void *data, size_t size);


/* sha1_hmac • compute the HMAC-SHA-1 of the given message with the given key*/
void
sha1_hmac(unsigned char output[20], const void *msg, size_t msg_size,
					const void *key, size_t key_size);

#endif /* ndef LITHIUM_SHA1_H */

/* vim: set filetype=c: */
