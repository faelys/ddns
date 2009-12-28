/* sha1.c - SHA-1 cryptographic hash function, RFC 3174 */

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sha1.h"

#include <stdio.h>
#include <string.h>


/*****************************************
 * FUNCTIONS AND CONSTANTS FROM RFC 3174 *
 *****************************************/

#define f1(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
	/* optimized from (((x) & (y)) | (~(x) & (z))) */
#define f2(x,y,z)  ((x) ^ (y) ^ (z))
#define f3(x,y,z)  (((x) & (y)) | ((z) & ((x) | (y))))
	/* optimized from (((x) & (y)) | ((x) & (z)) | ((y) & (z))) */
#define f4(x,y,z)  ((x) ^ (y) ^ (z))


#define K1	0x5A827999
#define K2	0x6ED9EBA1
#define K3	0x8F1BBCDC
#define K4	0xCA62C1D6



/****************
 * HELPER MACRO *
 ****************/

/* circular left shift S^n(X) = (X << n) OR (X >> 32-n) */
#define S(n,X) (((X) << (n)) | ((X) >> (32-(n))))



/***************************
 * STATIC HELPER FUNCTIONS *
 ***************************/

/* sha1_hash_block • update of the internal state when W(0…15) are filled */
static void
sha1_hash_block(struct sha1_state *s) {
	unsigned i;
	uint32_t temp;

	/* b. For t = 16 to 79 let
		W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)). */
	for (i = 16; i < 80; i += 1)
		s->W[i] = S(1, s->W[i-3] ^ s->W[i-8] ^ s->W[i-14] ^ s->W[i-16]);

	/* c. Let A = H0, B = H1, C = H2, D = H3, E = H4. */
	s->A = s->H[0];
	s->B = s->H[1];
	s->C = s->H[2];
	s->D = s->H[3];
	s->E = s->H[4];

	/* d. For t = 0 to 79 do
		TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
		E = D;  D = C;  C = S^30(B);  B = A; A = TEMP; */
	for (i = 0; i < 20; i += 1) {
		temp = S(5, s->A) + f1(s->B, s->C, s->D) + s->E + s->W[i] + K1;
		s->E = s->D;
		s->D = s->C;
		s->C = S(30, s->B);
		s->B = s->A;
		s->A = temp; }
	for (i = 20; i < 40; i += 1) {
		temp = S(5, s->A) + f2(s->B, s->C, s->D) + s->E + s->W[i] + K2;
		s->E = s->D;
		s->D = s->C;
		s->C = S(30, s->B);
		s->B = s->A;
		s->A = temp; }
	for (i = 40; i < 60; i += 1) {
		temp = S(5, s->A) + f3(s->B, s->C, s->D) + s->E + s->W[i] + K3;
		s->E = s->D;
		s->D = s->C;
		s->C = S(30, s->B);
		s->B = s->A;
		s->A = temp; }
	for (i = 60; i < 80; i += 1) {
		temp = S(5, s->A) + f4(s->B, s->C, s->D) + s->E + s->W[i] + K4;
		s->E = s->D;
		s->D = s->C;
		s->C = S(30, s->B);
		s->B = s->A;
		s->A = temp; }

	/* e. Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4
		+ E. */
	s->H[0] += s->A;
	s->H[1] += s->B;
	s->H[2] += s->C;
	s->H[3] += s->D;
	s->H[4] += s->E;

	/* clearing the next input memory zone */
	s->W[ 0] = s->W[ 1] = s->W[ 2] = s->W[ 3] =
	s->W[ 4] = s->W[ 5] = s->W[ 6] = s->W[ 7] =
	s->W[ 8] = s->W[ 9] = s->W[10] = s->W[11] =
	s->W[12] = s->W[13] = s->W[14] = s->W[15] = 0; }



/****************************
 * EXPORTED BASIC FUNCTIONS *
 ****************************/

/* sha1_init • initialization of the internal state */
void
sha1_init(struct sha1_state *state) {
	if (!state) return;
	state->H[0] = 0x67452301u;
	state->H[1] = 0xEFCDAB89u;
	state->H[2] = 0x98BADCFEu;
	state->H[3] = 0x10325476u;
	state->H[4] = 0xC3D2E1F0u;
	state->size = 0;
	state->W[ 0] = state->W[ 1] = state->W[ 2] = state->W[ 3] =
	state->W[ 4] = state->W[ 5] = state->W[ 6] = state->W[ 7] =
	state->W[ 8] = state->W[ 9] = state->W[10] = state->W[11] =
	state->W[12] = state->W[13] = state->W[14] = state->W[15] = 0; }


/* sha1_update • adds data to the internal state */
void
sha1_update(struct sha1_state *state, const void *data, size_t size) {
	const unsigned char *udata = data;
	unsigned idx;
	unsigned i = 0;

	/* sanity checks */
	if (!state || !data || !size) return;
	idx = state->size % 64;

	/* filling a partial word */
	if (idx & 3) {
		while ((idx & 3) != 0 && i < size) {
			state->W[idx / 4] |= udata[i] << (8*(3 - (idx & 3)));
			idx += 1;
			i += 1; }
		if (idx >= 64) {
			sha1_hash_block(state);
			idx = 0; }
		if (i >= size) {
			state->size += size;
			return; } }
	idx /= 4;

	/* filling complete words */
	while (i + 3 < size) {
		/* fill the current word */
		state->W[idx] = (udata[i] << 24)
				| (udata[i + 1] << 16)
				| (udata[i + 2] <<  8)
				| udata[i + 3];
		i += 4;
		idx += 1;

		/* hash the block when it is filled */
		if (idx >= 16) {
			sha1_hash_block(state);
			idx = 0; } }

	/* append the remaining bytes */
	if (i < size)
		state->W[idx] = (udata[i] << 24)
			| (i + 1 < size ? udata[i + 1] << 16 : 0)
			| (i + 2 < size ? udata[i + 2] <<  8 : 0);

	/* update the size in the state structure */
	state->size += size; }


/* sha1_finish • ends the hash and fills the output buffer with the value */
void
sha1_finish(struct sha1_state *state, unsigned char output[20]) {
	unsigned i;

	/* sanity checks */
	if (!state || !output) return;

	/* padding of the last byte */
	i = state->size % 64;
	state->W[i / 4] |= 0x80 << (8 * (3 - (i & 3)));

	/* completing the block if there is no room for the size field */
	if (i >= 56) sha1_hash_block(state);

	/* adding the size (in bits) at the end of the block */
	state->W[14] = (state->size >> 29) & 0xFFFFFFFF;
	state->W[15] = (state->size <<  3) & 0xFFFFFFFF;

	/* adding the final block */
	sha1_hash_block(state);

	/* copy of the hash into the output */
	for (i = 0; i < 5; i += 1) {
		output[i*4]     = (state->H[i] >> 24) & 0xFF;
		output[i*4 + 1] = (state->H[i] >> 16) & 0xFF;
		output[i*4 + 2] = (state->H[i] >>  8) & 0xFF;
		output[i*4 + 3] = (state->H[i])       & 0xFF; } }



/*******************************
 * EXPORTED ADVANCED FUNCTIONS *
 *******************************/

/* sha1_hash • performs a hash on the given complete message */
void
sha1_hash(unsigned char output[20], const void *data, size_t size) {
	struct sha1_state state;
	sha1_init(&state);
	sha1_update(&state, data, size);
	sha1_finish(&state, output); }


/* sha1_hmac • compute the HMAC-SHA-1 of the given message with the given key*/
void
sha1_hmac(unsigned char output[20], const void *msg, size_t msg_size,
					const void *key, size_t key_size) {
	unsigned char ukey[64];
	unsigned char hash[20];
	struct sha1_state state;
	unsigned i;

	/* sanity checks */
	if (!output || !msg || !msg_size || !key || !key_size) return;

	/* init. */
	memset(ukey, 0, sizeof ukey);

	/* if the key is longer than a block, use its hash insead */
	if (key_size > sizeof ukey)
		sha1_hash(ukey, key, key_size);
	else
		memcpy(ukey, key, key_size);

	/* inner hash: key ^ 0x36 (ipad), message */
	for (i = 0; i < sizeof ukey; i += 1) ukey[i] ^= 0x36;
	sha1_init(&state);
	sha1_update(&state, ukey, sizeof ukey);
	sha1_update(&state, msg, msg_size);
	sha1_finish(&state, hash);

	/* outer hash: key ^ 0x5C (opad), inner hash */
	for (i = 0; i < sizeof ukey; i += 1) ukey[i] ^= 0x36 ^ 0x5C;
	sha1_init(&state);
	sha1_update(&state, ukey, sizeof ukey);
	sha1_update(&state, hash, sizeof hash);
	sha1_finish(&state, output); }

/* vim: set filetype=c: */
