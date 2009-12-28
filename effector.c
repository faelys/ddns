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

#include <signal.h>
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
			const char *scmd = SX_DATA(SX_CHILD(s));
			if (!strcmp(scmd, "name")
			||  !strcmp(scmd, "host")
			||  !strcmp(scmd, "hostname"))
				csz += nsize;
			else if (!strcmp(scmd, "addr")
			||  !strcmp(scmd, "address"))
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


/* update_serial • updates the serial from a zone file */
static int
update_serial(char *serial) {
	time_t now;
	struct tm *tm;
	int year, month, day, nb;

	/* getting local time */
	now = time(0);
	tm  = gmtime(&now);

	/* decoding current serial */
	year =	  (serial[0] - '0') * 1000
		+ (serial[1] - '0') *  100
		+ (serial[2] - '0') *   10
		+ (serial[3] - '0');
	month =	  (serial[4] - '0') * 10
		+ (serial[5] - '0');
	day =	  (serial[6] - '0') * 10
		+ (serial[7] - '0');
	nb =	  (serial[8] - '0') * 10
		+ (serial[9] - '0');

	/* failing if serial is in the future */
	if (year > tm->tm_year + 1900
	|| (year == tm->tm_year + 1900 && month > tm->tm_mon + 1)
	|| (year == tm->tm_year + 1900 && month == tm->tm_mon + 1
					&& day > tm->tm_mday)
	|| (year == tm->tm_year + 1900 && month == tm->tm_mon + 1
					&& day == tm->tm_mday && nb >= 99))
		return -1;

	/* computing the new number */
	if (year == tm->tm_year + 1900
	&& month == tm->tm_mon + 1
	&& day   == tm->tm_mday)
		nb += 1;
	else
		nb = 1;

	/* encoding the new serial */
	serial[0] = '0' + (19 + tm->tm_year / 100) / 10;
	serial[1] = '0' + (19 + tm->tm_year / 100) % 10;
	serial[2] = '0' + (tm->tm_year % 100) / 10;
	serial[3] = '0' + (tm->tm_year % 100) % 10;
	serial[4] = '0' + (tm->tm_mon + 1) / 10;
	serial[5] = '0' + (tm->tm_mon + 1) % 10;
	serial[6] = '0' + tm->tm_mday / 10;
	serial[7] = '0' + tm->tm_mday % 10;
	serial[8] = '0' + nb / 10;
	serial[9] = '0' + nb % 10;
	return 0; }



/* effector_one_zone • updates a single zone file */
#define ZONE_BUF_UNIT	4096
static int
effector_one_zone(const char *filename, const char *name, size_t nsize,
						unsigned char addr[4]) {
	char *data = 0;
	size_t dsize = 0, asize = 0, ret, i, line, org, end, next;
	size_t ser_b, ser_e;
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

	/* looking for ten consecutive digits as a serial to update */
	ser_e = ser_b = 0;
	while (ser_e < dsize && ser_e - ser_b != 10) {
		ser_b = ser_e;
		while (ser_b < dsize
		&& (data[ser_b] < '0' || data[ser_b] > '9'))
			ser_b += 1;
		ser_e = ser_b;
		while (ser_e < dsize
		&& (data[ser_e] >= '0' && data[ser_e] <= '9'))
			ser_e += 1; }
	if (ser_e - ser_b != 10) {
		log_s_zone_no_serial(filename);
		return -1; }
	if (update_serial(data + ser_b) < 0) {
		log_s_zone_future_serial(data + ser_b, filename);
		return -1; }
		

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


/* effector_kill_one • sends a signal to the process from the given pidfile */
#define TESTSIG(x, st, si)	\
	else if (!strcasecmp(st, #x) || !strcasecmp(st, "SIG" #x)) \
		si = SIG ## x
static void
effector_kill_one(const char *signal, const char *pidfile) {
	int sig, i;
	FILE *f;
	pid_t pid;
	char c;

	/* signal decoding */
	if (!signal) sig = SIGHUP;
	TESTSIG(ABRT, signal, sig);
	TESTSIG(ALRM, signal, sig);
	TESTSIG(BUS, signal, sig);
	TESTSIG(CHLD, signal, sig);
	TESTSIG(CONT, signal, sig);
	TESTSIG(FPE, signal, sig);
	TESTSIG(HUP, signal, sig);
	TESTSIG(ILL, signal, sig);
	TESTSIG(INT, signal, sig);
	TESTSIG(KILL, signal, sig);
	TESTSIG(PIPE, signal, sig);
	TESTSIG(QUIT, signal, sig);
	TESTSIG(SEGV, signal, sig);
	TESTSIG(STOP, signal, sig);
	TESTSIG(TERM, signal, sig);
	TESTSIG(TSTP, signal, sig);
	TESTSIG(TTIN, signal, sig);
	TESTSIG(TTOU, signal, sig);
	TESTSIG(USR1, signal, sig);
	TESTSIG(USR2, signal, sig);
	TESTSIG(PROF, signal, sig);
/*	TESTSIG(POLL, signal, sig); */
	TESTSIG(SYS, signal, sig);
	TESTSIG(TRAP, signal, sig);
	TESTSIG(URG, signal, sig);
	TESTSIG(VTALRM, signal, sig);
	TESTSIG(XCPU, signal, sig);
	TESTSIG(XFSZ, signal, sig);
	else {
		i = 0;
		sig = 0;
		while (signal[i] >= '0' && signal[i] <= '9') {
			sig = sig * 10 + signal[i] - '0';
			i += 1; }
		if (signal[i] != 0) {
			log_s_effkill_bad_signal(signal, pidfile);
			return; } }

	/* pidfile reading */
	f = fopen(pidfile, "rb");
	if (!f) {
		log_s_effkill_open(pidfile);
		return; }
	pid = 0;
	while (fread(&c, 1, 1, f) > 0)
		if (c >= '0' && c <= '9') pid = pid * 10 + c - '0';
		else break;
	fclose(f);
	if (!pid) {
		log_s_effkill_bad_pidfile(pidfile);
		return; }

	/* sending signal */
	if (kill(pid, sig) < 0) {
		log_s_effkill_kill(pid, pidfile, sig, signal);
		return; } }


/* effector_kill_one_sx • sends a single signal described by a S-exp */
static void
effector_kill_one_sx(struct sx_node *sx) {
	if (!sx || !SX_IS_ATOM(sx)) return;
	if (sx->next && SX_IS_ATOM(sx->next))
		effector_kill_one(sx->data, sx->next->data);
	else
		effector_kill_one(0, sx->data); }


/* effector_kill • sends signals described by a S-exp */
static void
effector_kill(struct sx_node *sx, const char *name, size_t nsize,
						unsigned char addr[4]) {
	struct sx_node *s;

	(void)name;
	(void)nsize;
	(void)addr;

	if (SX_IS_LIST(sx))
		for (s = sx; s; s = s->next)
			effector_kill_one_sx(SX_CHILD(s));
	else
		effector_kill_one_sx(sx); }



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

		if (!strcmp(cmd, "kill"))
			effector_kill(arg, name, nsize, addr);
		else if (!strcmp(cmd, "system"))
			effector_system(arg, name, nsize, addr);
		else if (!strcmp(cmd, "zone"))
			effector_zone(arg, name, nsize, addr);
		else log_s_bad_effector(cmd); } }

/* vim: set filetype=c: */
