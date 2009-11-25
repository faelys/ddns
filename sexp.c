/* sexp.c - S-expression structure */

/*
 * Copyright (c) 2008, Natacha Porté
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

#include "sexp.h"

#include "array.h"

#include <stdlib.h>
#include <string.h>

#define PRETTY_PREFIX_UNIT	16
#define PARSER_BUF_UNIT		32


/***************
 * LOCAL TYPES *
 ***************/

/* struct sxp_state • state of the S-expression partser */
struct sxp_state {
	enum {
		SXP_BASE,
		SXP_TOKEN,
		SXP_QUOTED,
		SXP_VERBATIM,
		SXP_HEXA,
		SXP_BASE64,
		SXP_PREFIX }	state;	/* state of the parser */
	struct buf *		buf;	/* current token */
	struct parray		stack;	/* unfinished S-exp list */
	int			aux; };	/* auxiliary value for the cur state */



/**************************
 * S-EPXRESSION FUNCTIONS *
 **************************/

/* sx_append • appends an atom as a brother of an existing S-expression */
void
sx_append(struct sexp **base, struct sexp *neo) {
	struct sexp **prev = base;
	while (*prev)
		prev = &((*prev)->next);
	*prev = neo; }


/* sx_dup • deep-copy of a S-expression */
struct sexp *
sx_dup(const struct sexp *src) {
	struct sexp *ret = 0;
	struct sexp **prev = &ret;
	struct sexp *cur;
	while (src) {
		cur = sx_new(0, 0, 0);
		if (!cur) break;
		bufset(&cur->node, src->node);
		if (src->list) cur->list = sx_dup(src->list);
		*prev = cur;
		prev = &cur->next;
		src = src->next; }
	return ret; }


/* sx_findhead • finds a given string in a head of the children of the S-exp */
struct sexp *
sx_findhead(struct sexp *base, const char *token) {
	struct parray tosee;
	struct sexp* sx;
	/* sanity checks */
	if (base->node) {
		if (base->node->data
		&& !strncmp(token, base->node->data,
				base->node->size))
			return base;
		else	return 0; }
	if (!base->list) return 0;
	/* actual search */
	parr_init(&tosee);
	parr_push(&tosee, base->list);
	while ((sx = parr_remove(&tosee, 0)) != 0) {
		if (sx->node && sx->node->data
		&& !strncmp(token, sx->node->data, sx->node->size)) {
			parr_free(&tosee);
			return sx; }
		while (sx) {
			if (sx->list) parr_push(&tosee, sx->list);
			sx = sx->next; } }
	parr_free(&tosee);
	return 0; }


/* sx_free • deep-release of a S-expression */
void
sx_free(struct sexp *sx) {
	struct sexp *s = sx;
	while (s) {
		struct sexp *ne = s->next;
		bufrelease(s->node);
		if (s->list) sx_free(s->list);
		free(s);
		s = ne; } }


/* sx_new • allocation and initialization of a S-expression atom */
struct sexp *
sx_new(struct buf *a, struct sexp *b, struct sexp *c) {
	struct sexp* r = malloc(sizeof *r);
	if (r) {
		r->node = a;
		r->list = b;
		r->next = c; }
	return r; }


/* sx_bprint • compact S-expression output into a struct buf */
void
sx_bprint(struct buf *out, const struct sexp *sx) {
	const struct sexp *s = sx;
	while (s) {
		if (s->node) {
			bufprintf(out, "%zu:", s->node->size);
			bufput(out, s->node->data, s->node->size); }
		if (s->list) {
			bufputc(out, '(');
			sx_bprint(out, s->list);
			bufputc(out, ')'); }
		s = s->next; } }


/* sx_fprint • compact S-expression output into a FILE */
void
sx_fprint(FILE *out, const struct sexp *sx) {
	const struct sexp *s = sx;
	while (s) {
		if (s->node) {
			fprintf(out, "%zu:", s->node->size);
			fwrite(s->node->data, 1, s->node->size, out); }
		if (s->list) {
			fputc('(', out);
			sx_fprint(out, s->list);
			fputc(')', out); }
		s = s->next; } }


/* sx_print • pretty S-expression printing into a struct buf */
void
sx_print(struct buf *out, const struct sexp *sx, struct buf *pref) {
	const struct sexp *s = sx;
	struct buf *prefix = 0;
	if (pref) bufset(&prefix, pref);
	else prefix = bufnew(PRETTY_PREFIX_UNIT);
	while (s) {
		if (s->node) {
			if (s != sx) bufputc(out, ' ');
			sx_print_atom(out, s->node); }
		if (s->list) {
			if (s != sx) {
				bufputc(out, '\n');
				bufput(out, prefix->data, prefix->size); }
			bufputc(out, '(');
			bufputc(prefix, '\t');
			sx_print(out, s->list, prefix);
			prefix->size -= 1;
			bufputc(out, ')'); }
		s = s->next; }
	bufrelease(prefix); }


/* sx_print_atom • pretty print an atom
 * (token if possible, otherwise verbatim) */
void
sx_print_atom(struct buf *out, const struct buf *atom) {
	int i = 0, j = 0;
	while (i < atom->size
		 && atom->data[i] != ' '
		 && atom->data[i] != '\t'
		 && atom->data[i] != '\n'
		 && atom->data[i] != '\r'
		 && atom->data[i] != 0
		 && atom->data[i] != '('
		 && atom->data[i] != ')'
		 && atom->data[i] != '"'
		 && atom->data[i] != '#'
		 && atom->data[i] != '|') ++i;
	while (j < atom->size
		&& atom->data[j] >= '0'
		&& atom->data[j] <= '9') ++j;
	if (!atom->size
	|| i < atom->size
	|| (j < atom->size && atom->data[j] == ':')) {
		bufprintf(out, "%zu:", atom->size);
		bufput(out, atom->data, atom->size); }
	else
		bufput(out, atom->data, atom->size); }



/***************************
 * PARSER HELPER FUNCTIONS *
 ***************************/

/* sxp_append • appends a S-expression atom to the current state */
static inline void
sxp_append(struct sxp_state *s, struct sexp **base, struct sexp *neo) {
	if (s->stack.size) {
		struct sexp* first = s->stack.item[s->stack.size - 1];
		if (first) sx_append(&first, neo);
		else s->stack.item[s->stack.size - 1] = neo; }
	else sx_append(base, neo); }


/* sxp_addtoken • appends a new S-expression token to the cur state */
static inline void
sxp_addtoken(struct sxp_state *s, struct sexp **base) {
	sxp_append(s, base, sx_new(bufdup(s->buf, 1), 0, 0));
	s->buf->size = 0; }


/* sxp_addlist • appends a new S-expression list to the cur state */
static inline void
sxp_addlist(struct sxp_state *s, struct sexp **base) {
	sxp_append(s, base, sx_new(0, parr_pop(&s->stack), 0)); }


/* sxp_init • initialization of the content of a parser state structure */
static int
sxp_init(struct sxp_state *s) {
	s->state = SXP_BASE;
	s->buf = bufnew(PARSER_BUF_UNIT);
	if (s->buf == 0) {
		free(s);
		return 0; }
	parr_init(&s->stack);
	return 1; }


/* sxp_release • release of the content of a parser state structure */
static void
sxp_release(struct sxp_state *s) {
	if (s == 0) return;
	parr_free(&s->stack);
	bufrelease(s->buf); }



/*******************************
 * PER-STATE PARSING FUNCTIONS *
 *******************************/

/* parsing data while in basic state */
static inline int
sxp_parse_base(	struct sxp_state *s,
		const char *in,
		int first,
		int isz,
		struct sexp **pret) {
	int i = first;
	/* purging blanks and dispatching */
	while (i < isz && (in[i] == ' ' || in[i] == '\t'
			|| in[i] == '\n' || in[i] == '\r')) ++i;
	if (i >= isz) return i;
	else if (in[i] == '(')
		/* opening a new S-expression */
		parr_push(&s->stack, 0);
	else if (in[i] == ')') {
		/* closing a S-expression */
		if (s->stack.size) sxp_addlist(s, pret); }
	else if (in[i] == '#') {
		/* reading hexadecimal-encoded data */
		s->aux = -1;
		s->state = SXP_HEXA; }
	else if (in[i] == '"') {
		/* reading a quoted string */
		s->aux = 0;
		s->state = SXP_QUOTED; }
	else if (in[i] == '|')
		/* reading base-64 encoded data */
		s->state = SXP_BASE64;
	else if (in[i] >= '0' && in[i] <= '9') {
		/* reading a size prefix */
		s->state = SXP_PREFIX;
		i -= 1; }
	else {	/* reading a token */
		s->state = SXP_TOKEN;
		i -= 1; }
	return i; }


/* parsing base64 encoded data */
static inline int
sxp_parse_base64(	struct sxp_state *s,
			const char *in,
			int first,
			int isz,
			struct sexp **pret) {
	int i = first;
	int base = i;
	unsigned char acc[4];
	unsigned char c;
	int j, k = 0, o = 0;
	while (i < isz && in[i] != 0 && in[i] != '|') ++i;
	if (i > base) bufput(s->buf, in+base, i-base);
	if (i >= isz) return i;
	for (j = 0; j < s->buf->size; ++j) {
		const char in_c = s->buf->data[j];
		if (in_c >= 'A' && in_c <= 'Z')
			acc[k++] = s->buf->data[j] - 'A';
		else if (in_c >= 'a' && in_c <= 'z')
			acc[k++] = in_c - 'a' + 26;
		else if (in_c >= '0' && in_c <= '9')
			acc[k++] = in_c - '0' + 52;
		else if (in_c == '+')
			acc[k++] = 62;
		else if (in_c == '/')
			acc[k++] = 63;
		if (k == 4) {
			c=((acc[0])        << 2)|((acc[1] & 0x30) >> 4);
			s->buf->data[o++] = c;
			c=((acc[1] & 0x0f) << 4)|((acc[2] & 0x3c) >> 2);
			s->buf->data[o++] = c;
			c=((acc[2] & 0x03) << 6)| acc[3];
			s->buf->data[o++] = c;
			k = 0; } }
	if (k == 3) {
		c = ((acc[0])        << 2) | ((acc[1] & 0x30) >> 4);
		s->buf->data[o++] = c;
		c = ((acc[1] & 0x0f) << 4) | ((acc[2] & 0x3c) >> 2);
		s->buf->data[o++] = c; }
	else if (k == 2) {
		c = ((acc[0])        << 2) | ((acc[1] & 0x30) >> 4);
		s->buf->data[o++] = c; }
	s->buf->size = o;
	sxp_addtoken(s, pret);
	s->state = SXP_BASE;
	return i; }


/* parsing hexadecimal encoded data */
static inline int
sxp_parse_hexa(		struct sxp_state *s,
			const char *in,
			int first,
			int isz,
			struct sexp **pret) {
	int i = first;
	int num;
	while (i < isz && in[i] != 0 && in[i] != '#') {
		num = -1;
		if (in[i] >= '0' && in[i] <= '9')
			num = in[i] - '0';
		else if (in[i] >= 'a' && in[i] <= 'f')
			num = in[i] - 'a' + 10;
		else if (in[i] >= 'A' && in[i] <= 'F')
			num = in[i] - 'A' + 10;
		if (num >= 0) {
			if (s->aux < 0) s->aux = num;
			else {
				bufputc(s->buf, s->aux*16+num);
				s->aux = -1; } }
		++i; }
	if (i >= isz) {
		sxp_addtoken(s, pret);
		s->state = SXP_BASE; }
	return i; }


/* parsing a size prefix or a token beginning with digits */
static inline int
sxp_parse_prefix(	struct sxp_state *s,
			const char *in,
			int first,
			int isz,
			struct sexp **pret) {
	int i = first;
	int base = i;
	while (i < isz && in[i] >= '0' && in[i] <= '9') ++i;
	if (i > base) bufput(s->buf, in+base, i-base);
	if (i >= isz) return i;
	if (in[i] == ':') {
		/* that was a real prefix */
		bufputc(s->buf, 0);
		s->aux = atoi(s->buf->data);
		s->buf->size = 0;
		s->state = SXP_VERBATIM; }
	/* discarding length indication of quoted strings, */
	/* hexadecimal and base-64 encodings */
	else if (in[i] == '"') {
		s->buf->size = 0; s->state = SXP_QUOTED; }
	else if (in[i] == '#') {
		s->buf->size = 0; s->state = SXP_HEXA; }
	else if (in[i] == '|') {
		s->buf->size = 0; s->state = SXP_BASE64; }
	/* fallback on token representation (even though */
	/* standard forbids token beginning with digits) */
	else { --i; s->state = SXP_TOKEN; }
	return i; }


/* parsing a quoted string */
static inline int
sxp_parse_quoted(	struct sxp_state *s,
			const char *in,
			int first,
			int isz,
			struct sexp **pret) {
	int i = first;
	while (i < isz && (in[i] != '"' || s->aux == -1)) {
		if (s->aux == -1) {
			/* we're right after a backslash */
			s->aux = 0;
			if (in[i] == '\r' || in[i] == '\n')
				/* a newline is escaped */
				s->aux = 1000;
			else if (in[i] == 'x')
				/* hexadecimal character */
				s->aux = 2000;
			else if (in[i] == 'b') bufputc(s->buf, '\b');
			else if (in[i] == 't') bufputc(s->buf, '\t');
			else if (in[i] == 'v') bufputc(s->buf, '\v');
			else if (in[i] == 'n') bufputc(s->buf, '\n');
			else if (in[i] == 'f') bufputc(s->buf, '\f');
			else if (in[i] == 'r') bufputc(s->buf, '\r');
			else if (in[i] == '"' || in[i] == '\''
						|| in[i] == '\\')
				bufputc(s->buf, in[i]);
			else {
				bufputc(s->buf, '\\');
				bufputc(s->buf, in[i]); } }
		else if (s->aux == 1000) {
			/* escaping the second part of the newline */
			/* (if present) */
			s->aux = 0;
			if (in[i] != '\r' && in[i] != '\n')
				bufputc(s->buf, in[i]); }
		else if (s->aux == 2000) {
			/* first digit of a hexadecimal character */
			if (in[i] >= '0' && in[i] <= '9')
				s->aux = 3000 + in[i] - '0';
			else if (in[i] >= 'a' && in[i] <= 'f')
				s->aux = 3010 + in[i] - 'a';
			else if (in[i] >= 'A' && in[i] <= 'F')
				s->aux = 3010 + in[i] - 'A';
			else {	bufputs(s->buf, "\\x");
				bufputc(s->buf, in[i]); } }
		else if (s->aux >= 3000 && s->aux < 3016) {
			/* second digit of a hexadecimal characater */
			int t = (s->aux - 3000) * 16;
			if (in[i] >= '0' && in[i] <= '9')
				bufputc(s->buf, t + in[i] - '0');
			else if (in[i] >= 'a' && in[i] <= 'f')
				bufputc(s->buf, t + in[i] - 'a' + 10);
			else if (in[i] >= 'A' && in[i] <= 'F')
				bufputc(s->buf, t + in[i] - 'A' + 10);
			else {
				bufputs(s->buf, "\\x");
/* TODO:			butputc(s->buf,
 * 					character taken from s->aux);*/
				bufputc(s->buf, in[i]); }
			s->aux = 0; }
		else if (s->aux == 0) {
			/* regular character */
			if (in[i] == '\\') s->aux = -1;
			else bufputc(s->buf, in[i]); }
		++i; }
	if (i < isz) {
		sxp_addtoken(s, pret);
		s->state = SXP_BASE; }
	return i; }


/* parsing a token */
static inline int
sxp_parse_token(	struct sxp_state *s,
			const char *in,
			int first,
			int isz,
			struct sexp **pret) {
	int i = first;
	int base = i;
	while (i < isz && in[i] != ' ' && in[i] != '\t'
			&& in[i] != '\n' && in[i] != '\r' && in[i] != 0
			&& in[i] != '(' && in[i] != ')' && in[i] != '"'
			&& in[i] != '#' && in[i] != '|')
		++i;
	if (i > base) bufput(s->buf, in+base, i-base);
	if (i < isz) {
		sxp_addtoken(s, pret);
		s->state = SXP_BASE;
		--i; }
	return i; }


/* parsing verbatim data */
static inline int
sxp_parse_verbatim(	struct sxp_state *s,
			const char *in,
			int first,
			int isz,
			struct sexp **pret) {
	int i = first;
	if (isz - i >= s->aux - s->buf->size) {
		/* we're seeing the end */
		int sz = s->aux - s->buf->size;
		bufput(s->buf, in+i, sz);
		sxp_addtoken(s, pret);
		s->state = SXP_BASE;
		i += sz - 1; }
	else {	/* we're taking everything */
		bufput(s->buf, in+i, isz-i);
		i = isz; }
	return i; }



/*********************************
 * S-EXPRESSION PARSER FUNCTIONS *
 *********************************/

/* sxp_alloc • allocation of the (opaque) parser state structure */
struct sxp_state *
sxp_alloc(void) {
	struct sxp_state* s;
	s = malloc(sizeof (struct sxp_state));
	if (s == 0 || !sxp_init(s)) return 0;
	return s; }


/* sxp_free • releease of the parser state structure */
void
sxp_free(struct sxp_state *s) {
	sxp_release(s);
	free(s); }


/* sxp_parse • feeding data to the parser */
struct sexp *
sxp_parse(struct sxp_state *s, struct buf *buf_in) {
	int i, isz;
	const char* in;
	struct sexp* ret = 0;
	/* sanity checks */
	if (s == 0 || buf_in == 0
			|| buf_in->size <= 0
			|| buf_in->data == 0)
		return 0;
	in = buf_in->data;
	isz = buf_in->size;
	for (i = 0; i < isz; ++i)
		/* dispatching according to the current state */
		if (s->state == SXP_BASE)
			i = sxp_parse_base(s, in, i, isz, &ret);
		else if (s->state == SXP_TOKEN)
			i = sxp_parse_token(s, in, i, isz, &ret);
		else if (s->state == SXP_QUOTED)
			i = sxp_parse_quoted(s, in, i, isz, &ret);
		else if (s->state == SXP_VERBATIM)
			i = sxp_parse_verbatim(s, in, i, isz, &ret);
		else if (s->state == SXP_HEXA)
			i = sxp_parse_hexa(s, in, i, isz, &ret);
		else if (s->state == SXP_BASE64)
			i = sxp_parse_base64(s, in, i, isz, &ret);
		else if (s->state == SXP_PREFIX)
			i = sxp_parse_prefix(s, in, i, isz, &ret);
	return ret; }


/* sxp_read • full read of a FILE with a given chunk length */
struct sexp *
sxp_read(FILE *in, int datasize) {
	struct sxp_state state;
	struct sexp *ret = 0;
	struct sexp *sx;
	struct buf* buf;
	buf = bufnew(datasize);
	if (!bufgrow(buf, datasize)) return 0;
	sxp_init(&state);
	while (!feof(in) && !ferror(in)) {
		buf->size = fread(buf->data, 1, buf->asize, in);
		if (!buf->size) continue;
		sx = sxp_parse(&state, buf);
		if (sx) sx_append(&ret, sx); }
	sxp_release(&state);
	bufrelease(buf);
	return ret; }

/* vim: set filetype=c: */
