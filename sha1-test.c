/* sha1-test.c - test of my sha1 implementation */

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


/*********************************
 * TESTS TAKEN FROM THE RFC 3174 *
 *********************************/

#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
    /* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b
char *testarray[4] =
{
    TEST1,
    TEST2,
    TEST3,
    TEST4
};
long int repeatcount[4] = { 1, 1, 1000000, 10 };
char *resultarray[4] =
{
	"A9993E364706816ABA3E25717850C26C9CD0D89D",
	"84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
	"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
	"DEA356A2CDDD90C7A7ECEDC5EBB563934F460452"
};


void
rfc_test_hash(void) {
	struct sha1_state state;
	unsigned char hash[20];
	char hextbl[] = "0123456789ABCDEF";
	char hex[41];
	int i, j;

	hex[40] = 0;
	for (j = 0; j < 4; j += 1) {
		printf("Hash test %d: ", j + 1);
		sha1_init(&state);
		for (i = 0; i < repeatcount[j]; i += 1)
			sha1_update(&state, testarray[j], strlen(testarray[j]));
		sha1_finish(&state, hash);
		for (i = 0; i < 20; i += 1) {
			hex[2*i] = hextbl[hash[i] >> 4];
			hex[2*i+1] = hextbl[hash[i] & 15]; }
		if (!strcmp(hex, resultarray[j]))
			printf("OK\n");
		else	printf("FAILED\n   %ld, '%s'\n   out: %s\n   ref: %s\n",
				repeatcount[j], testarray[j],
				hex, resultarray[j]); } }



/*****************************
 * TESTS TAKEN FROM RFC 2202 *
 *****************************/

struct {
	const char *key;
	size_t key_size;
	const char *data;
	size_t data_size;
	const char *digest;
} hmac_test[] = { {
		"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
		"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
		20,
		"Hi There", 8,
		"b617318655057264e28bc0b6fb378c8ef146be00"
	}, {
		"Jefe", 4,
		"what do ya want for nothing?", 28,
		"effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
	}, {
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
		20,
		"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
		"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
		50,
		"125d7342b9ac11cd91a39af48aa17b4f63f175d3"
	}, {
		"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
		"\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
		"\x15\x16\x17\x18\x19",
		25,
		"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
		"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
		"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
		"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
		"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
		50,
		"4c9007f4026250c6bc8414f9bf50c86c2d7235da"
	}, {
		"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
		"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
		20,
		"Test With Truncation",
		20,
		"4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
	}, {
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
		80,
		"Test Using Larger Than Block-Size Key - Hash Key First",
		54,
		"aa4ae5e15272d00e95705637ce8a3b55ed402112"
	}, {
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
		"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
		80,
		"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
		73,
		"e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
	} };


static void
rfc_test_hmac(void) {
	unsigned i, j;
	unsigned char hash[20];
	char hextbl[] = "0123456789abcdef";
	char hex_hash[41];
	size_t nb = sizeof hmac_test / sizeof hmac_test[0];

	hex_hash[40] = 0;
	for (i = 0; i < nb; i += 1) {
		sha1_hmac(hash, hmac_test[i].data, hmac_test[i].data_size,
				hmac_test[i].key, hmac_test[i].key_size);
		for (j = 0; j < sizeof hash; j += 1) {
			hex_hash[2*j] = hextbl[hash[j] >> 4];
			hex_hash[2*j+1] = hextbl[hash[j] & 15]; }
		if (strcmp(hex_hash, hmac_test[i].digest))
			printf("HMAC test %u: FAILED\n\tout: %s\n\tref: %s\n",
					i + 1, hex_hash, hmac_test[i].digest);
		else	printf("HMAC test %u: OK\n", i + 1); } }



/************************
 * SHA-1 HASH OF A FILE *
 ************************/

#define READ_UNIT 1024

static void
sha1_file(FILE *in) {
	size_t sz, i;
	unsigned char buf[READ_UNIT];
	struct sha1_state state;

	sha1_init(&state);
	while ((sz = fread(buf, 1, READ_UNIT, in)) > 0)
		sha1_update(&state, buf, sz);
	sha1_finish(&state, buf);

	for (i = 0; i < 20; i += 1)
		printf("%02x", (unsigned)buf[i]);
	printf("\n"); }



/*****************
 * MAIN FUNCTION *
 *****************/

int
main(int argc, char **argv) {
	if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 0)
		sha1_file(stdin);
	else {
		rfc_test_hash();
		rfc_test_hmac(); }
	return 0; }

/* vim: set filetype=c: */
