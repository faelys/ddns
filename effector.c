/* effector.c - functions for actual DNS zone update */

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

#include "effector.h"

#include "log.h"

#include <stdlib.h>
#include <string.h>


/*****************************
 * SERVER EFFECTOR FUNCTIONS *
 *****************************/

/* effector_system • runs a subprocess */
/*	returns 0 on success, -1 on error */
static int
effector_system(struct sx_node *sx, const char *name, size_t nsize,
						unsigned char addr[4]) {
	struct sx_node *s;
	char *cmd;
	size_t csz, asize, i;
	int j;

	/* sanity checks */
	if (!sx || !name || !nsize || !addr) return -1;

	/* computing dotted address size */
	asize = 3 + ((addr[0] >= 100) ? 3 : (addr[0] >= 10) ? 2 : 1)
		  + ((addr[1] >= 100) ? 3 : (addr[1] >= 10) ? 2 : 1)
		  + ((addr[2] >= 100) ? 3 : (addr[2] >= 10) ? 2 : 1)
		  + ((addr[3] >= 100) ? 3 : (addr[3] >= 10) ? 2 : 1);

	/* computing command size */
	csz = 0;
	for (s = sx; s; s = s->next)
		if (SX_IS_ATOM(s)) csz += s->size;
		else if (SX_CHILD(s) && SX_IS_ATOM(SX_CHILD(s))) {
			if (!strcmp(SX_DATA(SX_CHILD(s)), "name")
			||  !strcmp(SX_DATA(SX_CHILD(s)), "host")
			||  !strcmp(SX_DATA(SX_CHILD(s)), "hostname"))
				csz += nsize;
			else if (!strcmp(SX_DATA(SX_CHILD(s)), "addr")
			||  !strcmp(SX_DATA(SX_CHILD(s)), "address"))
				csz += asize; }

	/* allocating command buffer */
	cmd = malloc(csz + 1);
	if (!cmd) {
		log_s_system_alloc(csz + 1);
		return -1; }

	/* building command line */
	i = 0;
	for (s = sx; s; s = s->next)
		if (SX_IS_ATOM(s)) {
			if (s->size) memcpy(cmd + i, s->data, s->size);
			i += s->size; }
		else if (SX_CHILD(s) && SX_IS_ATOM(SX_CHILD(s))) {
			const char *scmd = SX_DATA(SX_CHILD(s));
			if (!strcmp(scmd, "name")
			||  !strcmp(scmd, "host")
			||  !strcmp(scmd, "hostname")) {
				memcpy(cmd + i, name, nsize);
				i += nsize; }
			else if (!strcmp(scmd, "addr")
			|| !strcmp(scmd, "address")) {
				sprintf(cmd + i, "%u.%u.%u.%u",
					addr[0], addr[1], addr[2], addr[3]);
				i += asize; } }
	cmd[csz] = 0;

	/* subprocess spawn */
	j = system(cmd);
	if (j < 0) log_s_system(cmd);
	else if (j > 0) log_s_system_error(cmd, j);
	free(cmd);
	return j ? -1 : 0; }


/* effector_one_zone • updates a single zone file */
#define ZONE_BUF_UNIT	4096
static int
effector_one_zone(const char *filename, const char *name, size_t nsize,
						unsigned char addr[4]) {
	char *data = 0;
	size_t dsize = 0, asize = 0, ret, i, line, org, end, next;
	FILE *f;
	void *neo;
	log_s_zone_update(filename, name, nsize, addr);

	/* reading the file into an autoexpanding buffer */
	f = fopen(filename, "rb");
	if (!f) {
		log_s_zone_open_r(filename);
		return -1; }
	while (!feof(f) && !ferror(f)) {
		asize += ZONE_BUF_UNIT;
		neo = realloc(data, asize);
		if (!neo) {
			log_s_zone_realloc(filename, asize);
			free(data);
			fclose(f);
			return -1; }
		data = neo;
		ret = fread(data + dsize, 1, asize - dsize, f);
		dsize += ret; }
	fclose(f);

	/* scanning the buffer line by line, skipping the first one */
	line = org = end = next = 0;
	while (line < dsize) {
		/* going to the beginning of the next line */
		while (line < dsize
		&& data[line] != '\n' && data[line] != '\r')
			line += 1;
		while (line < dsize
		&& (data[line] == '\n' || data[line] == '\r'))
			line += 1;

		/* skipping leading whitespace and comments */
		org = line;
		while (org < dsize && (data[org] == ' ' || data[org] == '\t'
							|| data[org] == ';'))
			org += 1;

		/* checking hostname match */
		if (org + nsize >= dsize) break;
		if (strncmp(data + org, name, nsize))
			continue;

		/* checking record class */
		end = org + nsize;
		while (end < dsize && data[end] != '\n' && data[end] != '\r'
		&& !((data[end] == ' ' || data[end] == '\t')
		 && (data[end - 1] == 'a' || data[end - 1] == 'A')
		 && (data[end - 2] == ' ' || data[end - 2] == '\t')))
			end += 1;
		if (end >= dsize || data[end] == '\n' || data[end] == '\r')
			continue;

		/* looking for the line end */
		while (end < dsize && (data[end] == ' ' || data[end] == '\t'))
			end += 1;
		next = end;
		while (next < dsize && data[next] != '\n' && data[next] != '\r')
			next += 1;
		break; }

	/* nothing to do when a non-existent host goes down */
	if (!next && !addr[0] && !addr[1] && !addr[2] && !addr[3]) {
		free(data);
		return 0; }

	/* opening the zone file for writing */
	f = fopen(filename, "wb");
	if (!f) {
		log_s_zone_open_w(filename);
		return -1; }

	/* writing everything before the line */
	i = next ? line : dsize;
	ret = fwrite(data, 1, i, f);
	if (ret < i) log_s_zone_short_write(filename, ret, i);

	/* addition of a comment before a host went down */
	if (!addr[0] && !addr[1] && !addr[2] && !addr[3])
		fprintf(f, "; ");

	/* writing the constant part of the line */
	if (next) {
		i = end - org;
		ret = fwrite(data + org, 1, i, f);
		if (ret < i) log_s_zone_short_write(filename, ret, i); }
	else {
		ret = fwrite(name, 1, nsize, f);
		if (ret < nsize) log_s_zone_short_write(filename, ret, i);
		fprintf(f, " IN A "); }

	/* write the new address */
	fprintf(f, "%u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);

	/* writing the remaining of the file */
	if (next && next < dsize) {
		i = dsize - next;
		ret = fwrite(data + next, 1, i, f);
		if (ret < i) log_s_zone_short_write(filename, ret, i); }
	else
		fprintf(f, "\n");

	/* clean-up */
	fclose(f);
	free(data);
	return 0; }


/* effector_zone • updates a zone files described by a S-exp */
static void
effector_zone(struct sx_node *sx, const char *name, size_t nsize,
						unsigned char addr[4]) {
	struct sx_node *s;

	for (s = sx; s; s = s->next)
		if (SX_IS_ATOM(s) && s->size)
			effector_one_zone(s->data, name, nsize, addr); }



/*********************
 * EXPORTED FUNCTION *
 *********************/

/* set_addr • updates the recorded IP address of the given client */
/*	called with adress 0.0.0.0 on timeout */
void
set_addr(struct sx_node *sx, const char *name, size_t nsize,
						unsigned char addr[4]) {
	struct sx_node *s, *arg;
	const char *cmd;

	for (s = sx; s; s = s->next) {
		if (!s->data) continue;
		else if (SX_IS_ATOM(s)) {
			cmd = s->data;
			arg = 0; }
		else if (SX_IS_ATOM(SX_CHILD(s))) {
			cmd = SX_CHILD(s)->data;
			arg = SX_CHILD(s)->next; }
		else continue;

		if (!strcmp(cmd, "system"))
			effector_system(arg, name, nsize, addr);
		else if (!strcmp(cmd, "zone"))
			effector_zone(arg, name, nsize, addr);
		else log_s_bad_effector(cmd); } }

/* vim: set filetype=c: */
