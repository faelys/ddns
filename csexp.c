/* csexp.c - C-string based stand-alone S-expression functions */

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

#include "csexp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


/***************************
 * STATIC HELPER FUNCTIONS *
 ***************************/

/* sx_sizes • computes the data size and node number of a S-expression */
static void
sx_sizes(struct sx_node *root, size_t *dsize, size_t *nsize) {
	struct sx_node *node;

	for (node = root; node; node = node->next) {
		if (nsize) *nsize += 1;
		if (SX_IS_ATOM(node)) {
			if (dsize && node->size) *dsize += node->size + 1; }
		else sx_sizes(node->data, dsize, nsize); } }


/* sx_copy • copy the S-expression into a sexp assumed to be large enough */
static
void
sx_copy(struct sexp *sx, struct sx_node *root) {
	struct sx_node *src;
	struct sx_node *dst;
	struct sx_node *prev = 0;

	for (src = root; src; src = src->next) {
		dst = sx->nodes + sx->nsize;
		if (prev) prev->next = dst;
		sx->nsize += 1;
		prev = dst;
		if (SX_IS_ATOM(src)) {
			if (src->size) {
				dst->data = sx->data + sx->dsize;
				dst->size = src->size;
				memcpy(dst->data, src->data, dst->size);
				SX_DATA(dst)[dst->size] = 0;
				sx->dsize += dst->size; }
			else {
				dst->data = sx->data;
				dst->size = 0; } }
		else {
			dst->size = SX_LIST_MARK;
			if (src->data) {
				dst->data = dst + 1;
				sx_copy(sx, src->data); }
			else dst->data = 0; } } }


/* sxm_grow_data • realloc sexp.data if needed to fit the requested size */
/*	returns 0 on succes, -1 on failure */
/*	realloc() cannot be used here, because the old pointer can no longer
 *	    be used after a successful call to realloc(), which make node
 *	    rebase undefined behaviour. */
static int
sxm_grow_data(struct sx_mutable *sxm, size_t addition) {
	size_t needed, i;
	char *neo;
	/* no sanity check here */

	/* checks whether there is already enough room */
	needed = sxm->sx.dsize + addition;
	if (needed <= sxm->dasize) return 0;

	/* compute the new size (least multiple of dunit greater than needed)*/
	needed += sxm->dunit - ((needed - 1) % sxm->dunit + 1);
	assert(needed % sxm->dunit == 0);

	/* allocation of the new buffer */
	neo = malloc(needed);
	if (!neo) return -1;
	if (sxm->sx.dsize) memcpy(neo, sxm->sx.data, sxm->sx.dsize);

	/* rebase of all the atoms */
	for (i = 0; i < sxm->sx.nsize; i += 1)
		if (SX_IS_ATOM(sxm->sx.nodes + i))
			sxm->sx.nodes[i].data =
				neo + ((char *)sxm->sx.nodes[i].data
							- sxm->sx.data);

	/* release of the old buffer  and update of structures */
	free(sxm->sx.data);
	sxm->sx.data = neo;
	sxm->dasize = needed;
	return 0; }


/* sxm_grow_nodes • realloc sexp.nodes if needed to fit the requested size */
/*	returns 0 on succes, -1 on failure */
/*	realloc() cannot be used here, because the old pointer can no longer
 *	    be used after a successful call to realloc(), which make node
 *	    rebase undefined behaviour. */
static int
sxm_grow_nodes(struct sx_mutable *sxm, size_t addition) {
	size_t needed, i;
	struct sx_node *neo;
	/* no sanity check here */

	/* checks whether there is already enough room */
	needed = sxm->sx.nsize + addition;
	if (needed <= sxm->nasize) return 0;

	/* compute the new size (least multiple of nunit greater than needed)*/
	needed += sxm->nunit - ((needed - 1) % sxm->nunit + 1);
	assert(needed % sxm->nunit == 0);

	/* allocation of the new buffer */
	neo = malloc(needed * sizeof *neo);
	if (!neo) return -1;

	/* copy and rebase of all the nodes */
	for (i = 0; i < sxm->sx.nsize; i += 1) {
		neo[i].size = sxm->sx.nodes[i].size;
		if (SX_IS_ATOM(neo + i))
			neo[i].data = sxm->sx.nodes[i].data;
		else	neo[i].data = neo
				+ ((struct sx_node *)sxm->sx.nodes[i].data
				- sxm->sx.nodes);
		neo[i].next = neo + (sxm->sx.nodes[i].next - sxm->sx.nodes); }

	/* release of the old buffer  and update of structures */
	free(sxm->sx.nodes);
	sxm->sx.nodes = neo;
	sxm->nasize = needed;
	return 0; }



/*********************************
 * STATIC S-EXPRESSION FONCTIONS *
 *********************************/

/* sx_dup • creates a struct sexp from the given node */
/*	returns 0 on success, -1 on error */
/*	dest is overwritten with the new tightly-allocated S-expression */
/*	useful for sexp clean-up, pruning and sorting */
int
sx_dup(struct sexp *dest, struct sx_node *root) {
	size_t dsize, nsize;

	/* sanity checks */
	if (!dest || !root) return -1;

	/* computing the sizes needed */
	dsize = 1;
	nsize = 0;
	sx_sizes(root, &dsize, &nsize);

	/* memory allocation */
	dest->data = malloc(dsize);
	if (!dest->data) return -1;
	dest->nodes = malloc(nsize * sizeof *dest->nodes);
	if (!dest->nodes) {
		free(dest->data);
		return -1; }

	/* recursive node and data copy */
	dest->data[0] = 0;
	dest->dsize = 1;
	dest->nsize = 0;
	sx_copy(dest, root);
	assert(dest->dsize == dsize);
	assert(dest->nsize == nsize);
	return 0; }

/* sx_release • release pointers associated to a struct sexp */
void
sx_release(struct sexp *sx) {
	/* sanity check */
	if (!sx) return;

	/* release of internal pointers */
	free(sx->data);
	free(sx->nodes);

	/* safety reinit. of the structure */
	sx->data = 0;
	sx->nodes = 0;
	sx->dsize = sx->nsize = 0; }



/**********************************
 * MUTABLE S-EXPRESSION FUNCTIONS *
 **********************************/

/* sxm_add_atom • creates a new atom node with the given data */
/*	returns the newly created node, or 0 on error */
struct sx_node *
sxm_add_atom(struct sx_mutable *sxm, const void *data, size_t size,
						struct sx_node *next) {
	struct sx_node *node;

	/* sanity checks */
	if (!sxm || (size && !data)) return 0;

	/* grow sxm as needed */
	if (sxm_grow_data(sxm, size + 1) < 0
	||  sxm_grow_nodes(sxm, 1) < 0)
		return 0;

	/* node initialization */
	node = sxm->sx.nodes + sxm->sx.nsize;
	sxm->sx.nsize += 1;
	node->size = size;
	node->data = sxm->sx.data + (size ? sxm->sx.dsize : 0);
	node->next = next;

	/* data addition */
	if (size) {
		memcpy(node->data, data, size);
		SX_DATA(node)[size] = 0;
		sxm->sx.dsize += size + 1; }
	return node; }


/* sxm_add_list • creates a new list node with the given data */
/*	returns the newly created node, or 0 on error */
struct sx_node *
sxm_add_list(struct sx_mutable *sxm, struct sx_node *data,
						struct sx_node *next) {
	struct sx_node *node;

	/* sanity checks */
	if (!sxm) return 0;

	/* grow sxm as needed */
	if (sxm_grow_nodes(sxm, 1) < 0) return 0;

	/* filling in the node */
	node = sxm->sx.nodes + sxm->sx.nsize;
	sxm->sx.nsize += 1;
	node->size = SX_LIST_MARK;
	node->data = data;
	node->next = next;
	return node; }


/* sxm_init • initialisation of a struct sx_mutable */
/*	returns 0 on success, -1 on error */
int
sxm_init(struct sx_mutable *sxm, size_t dunit, size_t nunit) {
	/* sanity checks */
	if (!sxm || !dunit || !nunit) return -1;

	/* empty S-expression initialiation */
	sxm->sx.data = malloc(1);
	if (!sxm->sx.data) return -1;
	sxm->sx.data[0] = 0;
	sxm->sx.nodes = 0;
	sxm->sx.dsize = 1;
	sxm->sx.nsize = 0;

	/* mutator init. */
	sxm->dasize = sxm->nasize = 0;
	sxm->dunit = dunit;
	sxm->nunit = nunit;
	return 0; }


/* sxm_release • release internal memory of a struct sx_mutable */
/*	if keep is non-NULL, the internal struct sexp is copied into it
 *	    instead of being released */
void
sxm_release(struct sx_mutable *sxm, struct sexp *keep) {
	/* sanity check */
	if (!sxm) return;

	/* S-expression copy or release */
	if (keep) *keep = sxm->sx;
	else sx_release(&sxm->sx);

	/* safety reinit. of the structure */
	sxm->dasize = sxm->nasize = 0; }



/*********************************
 * S-EXPRESSION PARSER FUNCTIONS *
 *********************************/

/****** PARSER STATES *****/

#define SXP_BASE	0	/* basic state (outside of atoms) */
#define SXP_TOKEN	1	/* reading a token */
#define SXP_QUOTED	2	/* reading a quoted string */
#define SXP_VERBATIM	3	/* reading verbatim data */
#define SXP_HEXA	4	/* reading hexadecimal data */
#define SXP_BASE64	5	/* reading base64 data */
#define SXP_PREFIX	6	/* reading a numeric prefix */


static size_t sxp_base(struct sx_parser *, const char *, size_t);
static size_t sxp_token(struct sx_parser *, const char *, size_t);
static size_t sxp_quoted(struct sx_parser *, const char *, size_t);
static size_t sxp_verbatim(struct sx_parser *, const char *, size_t);
static size_t sxp_hexa(struct sx_parser *, const char *, size_t);
static size_t sxp_base64(struct sx_parser *, const char *, size_t);
static size_t sxp_prefix(struct sx_parser *, const char *, size_t);


/* parser dispatch table */
static size_t (*sxp_dispatch[])(struct sx_parser *, const char *, size_t) = {
	sxp_base,
	sxp_token,
	sxp_quoted,
	sxp_verbatim,
	sxp_hexa,
	sxp_base64,
	sxp_prefix };


/***** HELPER FUNCTIONS *****/

/* sxp_grow_atom • ensure there is at least 'size' bytes avail in 'atom' */
/*	returns 0 on succes, -1 on error */
static int
sxp_grow_atom(struct sx_parser *parser, size_t size) {
	void *neo;
	size_t need = parser->atom.size + size;
	if (need <= parser->atom.asize) return 0;
	need += parser->sxm.dunit - ((need - 1) % parser->sxm.dunit + 1);
	assert(need % parser->sxm.dunit == 0);
	neo = realloc(parser->atom.data, need);
	if (!neo) return -1;
	parser->atom.data = neo;
	parser->atom.asize = need;
	return 0; }

/* sxp_add_node • insert the given node */
static void
sxp_add_node(struct sx_parser *parser, struct sx_node *node) {
	if (parser->iprev != SX_LIST_MARK)
		parser->sxm.sx.nodes[parser->iprev].next = node;
	else if (parser->stack.size > 0)
		parser->sxm.sx.nodes[parser->stack.idx[parser->stack.size-1]].data
					= node;
	parser->iprev = node - parser->sxm.sx.nodes;  }


/* sxp_add_atom • insert the current atom as a node */
/*	returns 0 on succes, -1 on error */
static int
sxp_add_atom(struct sx_parser *parser) {
	struct sx_node *node;
	node = sxm_add_atom(&parser->sxm, parser->atom.data,
						parser->atom.size, 0);
	if (!node) return -1;
	sxp_add_node(parser, node);
	parser->atom.size = 0;
	return 0; }


/***** PER STATE PARSING FUNCTIONS *****/

/* sxp_base • parsing in the base state */
/*	aux is not used */
static size_t
sxp_base(struct sx_parser *parser, const char *data, size_t size) {
	size_t i = 0, r;
	struct sx_node *node;

	/* auxiliary variables clean-up */
	parser->aux = 0;

	/* skipping whitespace */
	while (i < size
	&& (data[i] == ' ' || data[i] == '\t'
	||  data[i] == '\n' || data[i] == '\r'))
		i += 1;
	if (i >= size) return i;

	/* opening a new S-expression */
	if (data[i] == '(') {
		node = sxm_add_list(&parser->sxm, 0, 0);
		if (!node) return 0;
		if (parser->stack.size >= parser->stack.asize) {
			size_t *neo;
			neo = realloc(parser->stack.idx,
				(parser->stack.asize + parser->sxm.nunit)
				* sizeof *neo);
			if (!neo) return 0;
			parser->stack.idx = neo;
			parser->stack.asize += parser->sxm.nunit; }
		sxp_add_node(parser, node);
		parser->stack.idx[parser->stack.size] = parser->iprev;
		parser->stack.size += 1;
		parser->iprev = SX_LIST_MARK;
		return i + 1; }

	/* closing the current S-expression */
	else if (data[i] == ')') {
		if (!parser->stack.size) return 1;
		parser->iprev = parser->stack.idx[parser->stack.size - 1];
		parser->stack.size -= 1;
		return i + 1; }

	/* updating the state if an atom is beginning */
	else if (data[i] == '"') {
		parser->state = SXP_QUOTED;
		return i + 1; }
	else if (data[i] == '#') {
		parser->state = SXP_HEXA;
		return i + 1; }
	else if (data[i] == '|') {
		parser->state = SXP_BASE64;
		return i + 1; }
	else if (data[i] >= '0' && data[i] <= '9') {
		parser->state = SXP_PREFIX;
		r = sxp_prefix(parser, data + i, size - i);
		return r ? i + r : 0; }
	else {
		parser->state = SXP_TOKEN;
		r = sxp_token(parser, data + i, size - i);
		return r ? i + r : 0; } }


/* sxp_verbatim • parsing verbatim data */
/*	aux is the number of bytes left to read */
static size_t
sxp_verbatim(struct sx_parser *parser, const char *data, size_t size) {
	if (size < parser->aux) {
		if (sxp_grow_atom(parser, size) < 0)
			return 0;
		memcpy(parser->atom.data + parser->atom.size, data, size);
		parser->atom.size += size;
		parser->aux -= size;
		return size; }
	else {
		if (sxp_grow_atom(parser, parser->aux) < 0)
			return 0;
		memcpy(parser->atom.data+parser->atom.size, data, parser->aux);
		parser->atom.size += parser->aux;
		if (sxp_add_atom(parser) < 0) return 0;
		parser->state = SXP_BASE;
		return parser->aux; } }


/* sxp_prefix • parsing a numeric prefix */
/*	aux is the number represented */
static size_t
sxp_prefix(struct sx_parser *parser, const char *data, size_t size) {
	size_t i = 0, r;

	/* reading figures into the atom and aux */
	while (i < size && data[i] >= '0' && data[i] <= '9') {
		parser->aux = parser->aux * 10 + data[i] - '0';
		i += 1; }
	if (i) {
		if (sxp_grow_atom(parser, i) < 0) return 0;
		memcpy(parser->atom.data + parser->atom.size, data, i);
		parser->atom.size += i; }
	if (i >= size) return i;

	/* discarding prefix of hexa and base64 tokens */
	if (data[i] == '#') {
		parser->state = SXP_HEXA;
		parser->atom.size = 0;
		parser->aux = 0;
		return i + 1; }
	else if (data[i] == '|') {
		parser->state = SXP_BASE64;
		parser->atom.size = 0;
		parser->aux = 0;
		return i + 1; }
	else if (data[i] == '"') {
		parser->state = SXP_QUOTED;
		parser->atom.size = 0;
		parser->aux = 0;
		return i + 1; }

	/* prefix of a verbatim atom */
	else if (data[i] == ':') {
		/* aux already contains the atom length */
		parser->atom.size = 0;
		parser->state = SXP_VERBATIM;
		return i + 1; }

	/* end of complete atom */
	else if (data[i] == '(' || data[i] == ')' || data[i] == '\n'
	|| data[i] == ' ' || data[i] == '\t' || data[i] == '\r') {
		if (sxp_add_atom(parser) < 0) return 0;
		parser->state = SXP_BASE;
		r = sxp_base(parser, data + i, size - i);
		return r ? i + r : 0; }

	/* part of an extended token */
	else {
		parser->state = SXP_TOKEN;
		r = sxp_token(parser, data + i, size - i);
		return r ? i + r : 0; } }


/* sxp_token • parsing an extended token */
/*	aux is not used */
static size_t
sxp_token(struct sx_parser *parser, const char *data, size_t size) {
	size_t i = 0, r;

	/* looking for the token end */
	while (i  < size
	&& data[i] != '\t' && data[i] != '\n' && data[i] != '\r'
	&& data[i] != ' ' && data[i] != '(' && data[i] != ')'
	&& data[i] != '#' && data[i] != '|' && data[i] != '"')
		i += 1;
	if (i) {
		if (sxp_grow_atom(parser, i) < 0) return 0;
		memcpy(parser->atom.data + parser->atom.size, data, i);
		parser->atom.size += i; }
	if (i >= size) return i;

	/* addition of the atom */
	if (sxp_add_atom(parser) < 0) return 0;
	parser->state = SXP_BASE;
	r = sxp_base(parser, data + i, size - i);
	return r ? i + r : 0; }


/* sxp_hexa • parsing a hexadecimally encoded atom */
/*	aux contains the previous character of a pair */
static size_t
sxp_hexa(struct sx_parser *parser, const char *data, size_t size) {
	size_t i = 0;
	unsigned char u;

	for (;;) {
		/* skipping inactive characters */
		while (i < size && data[i] != '#'
		&& !(data[i] >= '0' && data[i] <= '9')
		&& !(data[i] >= 'a' && data[i] <= 'f')
		&& !(data[i] >= 'A' && data[i] <= 'F'))
			i += 1;

		/* exiting loop on buffer or atom end */
		if (i >= size) return i;
		if (data[i] == '#') break;

		/* first chars of a pair is just stored */
		if (parser->aux == 0) {
			parser->aux = data[i];
			i += 1;
			continue; }

		/* second char is combined with aux into a byte */
		if (parser->aux >= '0' && parser->aux <= '9')
			u = parser->aux - '0';
		else if (parser->aux >= 'a' && parser->aux <= 'f')
			u = parser->aux - 'a' + 10;
		else if (parser->aux >= 'A' && parser->aux <= 'F')
			u = parser->aux - 'A' + 10;
		else u = 0; /* this should never happen */
		u *= 16;
		if (data[i] >= '0' && data[i] <= '9')
			u += data[i] - '0';
		else if (data[i] >= 'a' && data[i] <= 'f')
			u += data[i] - 'a' + 10;
		else if (data[i] >= 'A' && data[i] <= 'F')
			u += data[i] - 'A' + 10;
		if (sxp_grow_atom(parser, 1) < 0) return 0;
		i += 1;
		parser->aux = 0;
		parser->atom.data[parser->atom.size] = *(char *)&u;
		parser->atom.size += 1; }

	/* end of atom (data[i] == '#') */
	if (sxp_add_atom(parser) < 0) return 0;
	parser->state = SXP_BASE;
	return i + 1; }


/* base64_val • return the base-64 value of the given char */
static unsigned char
base64_val(char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return 255; } /* error */


/* sxp_base64 • parsing a base-64 encoded atom */
/*	aux conatined the nomber of decoded bytes so far */
static size_t
sxp_base64(struct sx_parser *parser, const char *data, size_t size) {
	size_t i = 0;
	unsigned char a, b, c, d, u;

	for (;;) {
		/* skipping inactive characters */
		while (i < size && data[i] != '|'
		&& data[i] != '+' && data[i] != '/'
		&& !(data[i] >= '0' && data[i] <= '9')
		&& !(data[i] >= 'a' && data[i] <= 'z')
		&& !(data[i] >= 'A' && data[i] <= 'Z'))
			i += 1;

		/* exiting loop on buffer or atom end */
		if (i >= size) return i;
		if (data[i] == '|') break;

		/* addition of the char to the atom buffer */
		if (sxp_grow_atom(parser, 1) < 0) return 0;
		parser->atom.data[parser->atom.size ++] = data[i++];

		/* processing a quadruplet */
		if (parser->atom.size < parser->aux + 4) continue;
		a = base64_val(parser->atom.data[parser->aux]);
		b = base64_val(parser->atom.data[parser->aux + 1]);
		c = base64_val(parser->atom.data[parser->aux + 2]);
		d = base64_val(parser->atom.data[parser->aux + 3]);
		u = (a << 2) | ((b & 0x30) >> 4);
		parser->atom.data[parser->aux] = *(char *)&u;
		u = ((b & 0x0f) << 4) | ((c & 0x3c) >> 2);
		parser->atom.data[parser->aux + 1] = *(char *)&u;
		u = ((c & 0x03) << 6) | d;
		parser->atom.data[parser->aux + 2] = *(char *)&u;
		parser->aux += 3;
		parser->atom.size = parser->aux; }

	/* processing extra bytes */
	a = b = c = d = 0;
	if (parser->atom.size >= parser->aux + 2) {
		a = base64_val(parser->atom.data[parser->aux]);
		b = base64_val(parser->atom.data[parser->aux + 1]);
		u = (a << 2) | ((b & 0x30) >> 4);
		parser->atom.data[parser->aux] = *(char *)&u; }
	if (parser->atom.size >= parser->aux + 3) {
		c = base64_val(parser->atom.data[parser->aux + 2]);
		u = ((b & 0x0f) << 4) | ((c & 0x3c) >> 2);
		parser->atom.data[parser->aux + 1] = *(char *)&u; }
	if (parser->atom.size >= parser->aux + 4) {
		d = base64_val(parser->atom.data[parser->aux + 3]);
		u = ((c & 0x03) << 6) | d;
		parser->atom.data[parser->aux + 2] = *(char *)&u; }
	if (parser->atom.size > parser->aux) parser->atom.size -= 1;

	/* end of atom */
	if (sxp_add_atom(parser) < 0) return 0;
	parser->state = SXP_BASE;
	return i + 1; }


/* sxp_quoted • parsing of a quoted-string atom */
/*	aux has a lot of escpae-related meanings */
static size_t
sxp_quoted(struct sx_parser *parser, const char *data, size_t size) {
	size_t i = 0;
	unsigned char u;

	for (i = 0; i < size; i += 1)
		/* aux == 0, basic state, copying inactive characters */
		if (parser->aux == 0) {
			size_t org = i;
			while (i < size && data[i] != '"' && data[i] != '\\')
				i += 1;
			if (org < i) {
				if (sxp_grow_atom(parser, i - org) < 0)
					return 0;
				memcpy(parser->atom.data + parser->atom.size,
						data, i - org);
				parser->atom.size += i - org; }
			if (i >= size) return i;
			if (data[i] == '"') break; /* end of atom */
			/* here data[i] == '\\' */
			parser->aux = 1000; }

		/* aux == 1000, first char after a backslash */
		else if (parser->aux == 1000) {
			char c = 0;
			if (data[i] == 'x')
				parser->aux = 2000;
			else if (data[i] == '\n' || data[i] == '\r')
				parser->aux = 4000 + data[i];
			else if (data[i] == 'b') c = '\b';
			else if (data[i] == 't') c = '\t';
			else if (data[i] == 'v') c = '\v';
			else if (data[i] == 'n') c = '\n';
			else if (data[i] == 'f') c = '\f';
			else if (data[i] == 'r') c = '\r';
			else if (data[i] == '"'
			|| data[i] == '\'' || data[i] == '\\')
				c = data[i];
			else if (data[i] >= '0' && data[i] <= '3')
				parser->aux = 5000 + (data[i] - '0') * 64;
			else {
				if (sxp_grow_atom(parser, 2) < 0) return 0;
				parser->atom.data[parser->atom.size++] = '\\';
				parser->atom.data[parser->atom.size++]
								= data[i];
				parser->aux = 0; }
			if (c) {
				if (sxp_grow_atom(parser, 1) < 0) return 0;
				parser->atom.data[parser->atom.size++] = c;
				parser->aux = 0; } }

		/* aux == 2000, first char of a hex escape */
		else if (parser->aux == 2000) {
			if (data[i] >= '0' && data[i] <= '9')
				parser->aux = 3000 + data[i] - '0';
			else if (data[i] >= 'a' && data[i] <= 'f')
				parser->aux = 3000 + data[i] - 'a' + 10;
			else if (data[i] >= 'A' && data[i] <= 'F')
				parser->aux = 3500 + data[i] - 'A' + 10;
			else {
				if (sxp_grow_atom(parser, 3) < 0) return 0;
				parser->atom.data[parser->atom.size++] = '\\';
				parser->atom.data[parser->atom.size++] = 'x';
				parser->atom.data[parser->atom.size++]
								= data[i];
				parser->aux = 0; } }

		/* aux == 3xxx, second char of a hex escape */
		else if (parser->aux >= 3000 && parser->aux < 4000) {
			u = 255;
			if (data[i] >= '0' && data[i] <= '9')
				u = data[i] - '0';
			else if (data[i] >= 'a' && data[i] <= 'f')
				u = data[i] - 'a' + 10;
			else if (data[i] >= 'A' && data[i] <= 'F')
				u = data[i] - 'A' + 10;
			else {
				if (sxp_grow_atom(parser, 4) < 0) return 0;
				parser->atom.data[parser->atom.size++] = '\\';
				parser->atom.data[parser->atom.size++] = 'x';
				parser->atom.data[parser->atom.size++] =
					parser->aux >= 3500
					? 'A' + (parser->aux - 3500) - 10
					: parser->aux >= 3010
					? 'a' + (parser->aux - 3000) - 10
					: '0' + (parser->aux - 3000);
				parser->atom.data[parser->atom.size++]
								= data[i]; }
			if (u < 16) {
				if (parser->aux >= 3500)
					u |= (parser->aux - 3500) << 4;
				else	u |= (parser->aux - 3000) << 4;
				if (sxp_grow_atom(parser, 1) < 0) return 0;
				parser->atom.data[parser->atom.size++]
							= *(char *)&u; }
			parser->aux = 0; }

		/* aux == 40xx, second char after an ignored newline */
		else if (parser->aux >= 4000 && parser->aux < 5000) {
			if ((parser->aux == 4000 + '\n' && data[i] != '\r')
			||  (parser->aux == 4000 + '\r' && data[i] != '\n')) {
				if (sxp_grow_atom(parser, 1) < 0) return 0;
				parser->atom.data[parser->atom.size++]
							= data[i]; }
			parser->aux = 0; }

		/* aux == 50xx, second char of an octal escape */
		else if (parser->aux >= 5000 && parser->aux < 6000) {
			if (data[i] >= '0' && data[i] <= '7')
				parser->aux += 1000 + (data[i] - '0') * 8;
			else {
				if (sxp_grow_atom(parser, 3) < 0) return 0;
				parser->atom.data[parser->atom.size++] = '\\';
				parser->atom.data[parser->atom.size++]
					= '0' + (parser->aux - 5000) / 64;
				parser->atom.data[parser->atom.size++]
							= data[i];
				parser->aux = 0; } }

		/* aux = 60xx, third char of an octal escape */
		else if (parser->aux >= 6000 && parser->aux < 7000) {
			if (data[i] >= '0' && data[i] <= '7') {
				u = (parser->aux - 6000) + (data[i] - '0');
				if (sxp_grow_atom(parser, 1) < 0) return 0;
				parser->atom.data[parser->atom.size++]
							= *(char *)&u; }
			else {
				if (sxp_grow_atom(parser, 3) < 0) return 0;
				parser->atom.data[parser->atom.size++] = '\\';
				parser->atom.data[parser->atom.size++]
					= '0' + (parser->aux - 6000) / 64;
				parser->atom.data[parser->atom.size++]
					= '0' + ((parser->aux - 6000) / 8) % 8;
				parser->atom.data[parser->atom.size++]
							= data[i]; }
			parser->aux = 0; }

		else return 0; /* inconsistent state */

	/* adding atom if it's over */
	if (i >= size) return i;
	if (data[i] != '"') return 0; /* inconsistent state */
	if (sxp_add_atom(parser) < 0) return 0;
	parser->state = SXP_BASE;
	return i + 1; }



/* sxp_parse • feeding data into the parser */
/*	returns 0 on succes, -1 on error */
int
sxp_parse(struct sx_parser *parser, const void *data, size_t size) {
	const char *cdata = data;
	size_t orig = 0, ret;

	if (!parser || !data) return -1;
	while (orig < size) {
		ret = (sxp_dispatch[parser->state])(parser,
						cdata+orig, size-orig);
		if (!ret) return -1;
		orig += ret; }
	return 0; }


/* sxp_file_to_sx • reads a file into a temporary sx_parser and fills a sx */
/*	returns 0 on succes, -1 on error */
int
sxp_file_to_sx(struct sexp *out, FILE *in, size_t readsize,
						size_t dunit, size_t nunit) {
	struct sx_parser parser;
	if (sxp_init(&parser, dunit, nunit) < 0
	||  sxp_readfile(&parser, in, readsize) < 0)
		return -1;
	sxp_release(&parser, 0, out);
	return 0; }

/* sxp_file_to_sxm • reads a file into a temporary sx_parser and fills a sxm */
/*	returns 0 on succes, -1 on error */
int
sxp_file_to_sxm(struct sx_mutable *out, FILE *in, size_t readsize,
						size_t dunit, size_t nunit) {
	struct sx_parser parser;
	if (sxp_init(&parser, dunit, nunit) < 0
	||  sxp_readfile(&parser, in, readsize) < 0)
		return -1;
	sxp_release(&parser, out, 0);
	return 0; }


/* sxp_init • initializes a struct sx_parser */
/*	returns 0 on succes, -1 on error */
int
sxp_init(struct sx_parser *parser, size_t dunit, size_t nunit) {
	if (!parser || !dunit || !nunit) return -1;
	if (sxm_init(&parser->sxm, dunit, nunit) < 0) return -1;
	parser->state = SXP_BASE;
	parser->aux = 0;
	parser->iprev = SX_LIST_MARK;
	parser->atom.data = 0;
	parser->atom.size = parser->atom.asize = 0;
	parser->stack.idx = 0;
	parser->stack.size = parser->stack.asize = 0;
	return 0; }


/* sxp_readfile • feeds data read from a file into the parser */
/*	returns 0 on succes, -1 on error */
int
sxp_readfile(struct sx_parser *parser, FILE *in, size_t bufsize) {
	size_t readsz;
	char *buf;

	/* sanity checks and allocation */
	if (!parser || !in) return -1;
	buf = malloc(bufsize);
	if (!buf) return -1;

	/* reading data as long as posible */
	while (!feof(in) && !ferror(in)) {
		readsz = fread(buf, 1, bufsize, in);
		if (!readsz) continue;
		if (sxp_parse(parser, buf, readsz) < 0)
			return -1; }

	/* clean-up */
	free(buf);
	return 0; }


/* sxp_release • release internal memory of a struct sx_parser */
/*	if keep_sxm is non-NULL, the internal struct sx_mutable is copied into
 *	    it instead of being released.
 *	if keep_sxm is NULL and keep_sx is non-NULL, the internal struct sexp
 *	    is copied into *keep_sx and the rest is released. */
void
sxp_release(struct sx_parser *parser, struct sx_mutable *keep_sxm,
							struct sexp *keep_sx) {
	if (!parser) return;
	if (keep_sxm) *keep_sxm = parser->sxm;
	else sxm_release(&parser->sxm, keep_sx);
	free(parser->atom.data);
	free(parser->stack.idx);
	parser->atom.size = parser->atom.asize = 0;
	parser->stack.size = parser->stack.asize = 0; }


/* vim: set filetype=c: */
