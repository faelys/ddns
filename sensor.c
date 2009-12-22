/* sensor.c - functions for self IP address discovery */

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

#include "sensor.h"

#include "log.h"

#include <string.h>


/******************
 * SENSOR METHODS *
 ******************/

/* sensor_system • get the address by calling a subprocess */
/*	returns 0 on success, -1 on error */
/*	The subprocess is given by the first argument node, which is popen()ed
 *	    the subprocess is expected to write the dotted numeric
 *	    representation of the IPv4 address alone on a single line. */
static int
sensor_system(unsigned char addr[4], struct sx_node *arg) {
	FILE *pipe;
	char buf[16]; /* 12 bytes is enough */
	unsigned char out[4];
	size_t sz;
	unsigned i, j;

	/* sanity checks */
	if (!addr || !arg || !SX_IS_ATOM(arg)) return -1;

	/* reading piped data */
	pipe = popen(arg->data, "r");
	if (!pipe) {
		log_c_pipe_error(arg->data);
		return -1; }
	sz = fread(buf, 1, sizeof buf, pipe);
	fclose(pipe);
	if (!sz) {
		log_c_pipe_read_error(arg->data);
		return -1; }

	/* decoding buffer */
	j = 0;
	out[0] = out[1] = out[2] = out[3] = 0;
	for (i = 0; i < sz; i += 1)
		if (buf[i] >= '0' && buf[i] <= '9')
			out[j] = out[j] * 10 + buf[i] - '0';
		else if (buf[i] == '.' && j < 3)
			j += 1;
		else break;
	if (i >= sz
	|| (buf[i] != '\n' && buf[i] != '\r')
	|| j < 3) {
		log_c_pipe_bad_addr(buf, sz);
		return -1; }

	/* returning data */
	addr[0] = out[0];
	addr[1] = out[1];
	addr[2] = out[2];
	addr[3] = out[3];
	return 0; }



/*********************
 * EXPORTED FUNCTION *
 *********************/

/* get_own_addr • returns the client's own IP address by interpreting the
 *		given S-expression */
/*	returns 0 on success, -1 on error */
int
get_own_addr(unsigned char addr[4], struct sx_node *sx) {
	struct sx_node *s, *arg;
	const char *cmd;

	addr[0] = addr[1] = addr[2] = addr[3] = 0;
	for (s = sx; s; s = s->next) {
		if (!s->data) continue;
		else if (SX_IS_ATOM(s)) {
			cmd = s->data;
			arg = 0; }
		else if (SX_IS_ATOM(SX_CHILD(s))) {
			cmd = SX_CHILD(s)->data;
			arg = SX_CHILD(s)->next; }
		else continue;
		if (!strcmp(cmd, "system")) {
			if (sensor_system(addr, arg) >= 0) return 0; }
		else log_c_bad_sensor(cmd); }
	addr[0] = addr[1] = addr[2] = addr[3] = 0;
	return -1; }

/* vim: set filetype=c: */
