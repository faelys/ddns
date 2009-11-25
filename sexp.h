/* sexp.h - S-expression structure */

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

#ifndef LITHIUM_SEXP_H
#define LITHIUM_SEXP_H

#include "buffer.h"

#include <stdio.h>


/********************
 * TYPE DEFINITIONS *
 ********************/

/* struct sexp • S-expression atom */
struct sexp {
	struct buf *	node;
	struct sexp *	list;
	struct sexp *	next; };


/* struct sxp_state • state of the S-expression partser */
struct sxp_state;



/**************************
 * S-EXPRESSION FUNCTIONS *
 **************************/

/* sx_append • appends an atom as a brother of an existing S-expression */
void
sx_append(struct sexp **, struct sexp *);

/* sx_dup • deep-copy of a S-expression */
struct sexp *
sx_dup(const struct sexp *)
	__attribute__ ((malloc));

/* sx_findhead • finds a given string in a head of the children of the S-exp */
struct sexp *
sx_findhead(struct sexp *, const char *);

/* sx_free • deep-release of a S-expression */
void
sx_free(struct sexp *);

/* sx_new • allocation and initialization of a S-expression atom */
struct sexp *
sx_new(struct buf *, struct sexp *, struct sexp *)
	__attribute__ ((malloc));

/* sx_bprint • compact S-expression output into a struct buf */
void
sx_bprint(struct buf *, const struct sexp *);

/* sx_fprint • compact S-expression output into a FILE */
void
sx_fprint(FILE *, const struct sexp *);

/* sx_print • pretty S-expression printing into a struct buf */
void
sx_print(struct buf *, const struct sexp *, struct buf *);

/* sx_print_atom • pretty print an atom
 * (token if possible, otherwise verbatim) */
void
sx_print_atom(struct buf *, const struct buf *);



/*********************************
 * S-EXPRESSION PARSER FUNCTIONS *
 *********************************/

/* sxp_alloc • allocation of the (opaque) parser state structure */
struct sxp_state *
sxp_alloc(void)
	 __attribute__ ((malloc));

/* sxp_free • releease of the parser state structure */
void
sxp_free(struct sxp_state *);

/* sxp_parse • feeding data to the parser */
struct sexp *
sxp_parse(struct sxp_state *, struct buf *);

/* sxp_read • full read of a FILE with a given chunk length */
struct sexp *
sxp_read(FILE*, int);

#endif /* ndef LITHIUM_SEXP_H */

/* vim: set filetype=c: */
