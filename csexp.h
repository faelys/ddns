/* csexp.h - C-string based stand-alone S-expression functions */

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

/*
 ***** COMPILE-TIME KNOBS *****
 *
 * HAVE_CONFIG_H
 *	includes "config.h" for further knobbing
 * WITHOUT_SX_MUTABLE
 *	disables mutable S-expression code. Implies WITHOUT_SX_PARSER
 * WITHOUT_SX_PARSER
 *	disables S-expression parser code.
 */

#ifndef LITHIUM_CSEXP_H
#define LITHIUM_CSEXP_H

#include <stdio.h>


/************************
 * MACROS AND CONSTANTS *
 ************************/

/* SX_LIST_MARK • when a node is a list, its size has this value */
#define SX_LIST_MARK	((size_t) -1)



/* SX_IS_ATOM • non-zero if the given struct sx_node * is an atom */
#define SX_IS_ATOM(x)	((x)->size != SX_LIST_MARK)

/* SX_IS_LIST • non-zero if the given struct sx_node * is a list */
#define SX_IS_LIST(x)	((x)->size == SX_LIST_MARK)



/* SX_CHILD • returns the first child of a list node */
#define SX_CHILD(x)	((struct sx_node *)(SX_IS_LIST(x) ? (x)->data : 0))

/* SX_DATA • returns the atom data if the given node is an atom */
#define SX_DATA(x)	((char *)(SX_IS_ATOM(x) ? (x)->data : 0))

/* SX_UDATA • returns the atom data if the given node is an atom */
#define SX_UDATA(x)	((unsigned char *)(SX_IS_ATOM(x) ? (x)->data : 0))



/********************
 * TYPE DEFINITIONS *
 ********************/

/* sx_node • structure for a node inside a S-expression */
struct sx_node {
	void		*data; /* either a char * or a struct sx_node * */
	size_t		 size; /* size of the atom data, or SX_LIST_MARK */
	struct sx_node	*next; /* pointer to the next borther node */
};


/* sexp • container for static S-expression and the node data */
struct sexp {
	char		*data;	/* concatenation of all node content */
	size_t		 dsize;	/* size of data, in bytes */
	struct sx_node	*nodes;	/* array of nodes */
	size_t		 nsize; /* number of nodes in the array */
};

#ifndef WITHOUT_SX_MUTABLE
/* sx_mutable • container for mutable S-expression */
struct sx_mutable {
	struct sexp	sx;	/* actual S-expression */
	size_t		dasize;	/* allocated size of sexp.data */
	size_t		dunit;	/* size of an extension chuck of sexp.data */
	size_t		nasize;	/* number of allocated nodes in sexp.nodes */
	size_t		nunit;	/* sexp.nodes extension unit */
};

#ifndef WITHOUT_SX_PARSER
/* sx_parser • S-expression parser data */
struct sx_parser {
	struct sx_mutable	 sxm;	/* S-expr in construction */
	int			 state;	/* current state of the parser */
	size_t			 aux;	/* auxiliary state */
	size_t			 iprev;	/* node index to link current node */
	struct {
		char		*data;
		size_t		 size;
		size_t		 asize;
	}			 atom;	/* current atom */
	struct {
		size_t		*idx;
		size_t		 size;
		size_t		 asize;
	}			 stack;	/* stack of indices of opened lists */
};
#endif /* ndef WITHOUT_SX_PARSER */
#endif /* ndef WITHOUT_SX_MUTABLE */



/*********************************
 * STATIC S-EXPRESSION FONCTIONS *
 *********************************/

/* sx_dup • creates a struct sexp from the given node */
/*	returns 0 on success, -1 on error */
/*	dest is overwritten with the new tightly-allocated S-expression */
/*	useful for sexp clean-up, pruning and sorting */
int
sx_dup(struct sexp *dest, struct sx_node *root);


/* sx_release • release pointers associated to a struct sexp */
/*	only content is freed, not the given pointer */
void
sx_release(struct sexp *sx);



/**********************************
 * MUTABLE S-EXPRESSION FUNCTIONS *
 **********************************/

#ifndef WITHOUT_SX_MUTABLE

/* sxm_add_atom • creates a new atom node with the given data */
/*	returns the newly created node, or 0 on error */
struct sx_node *
sxm_add_atom(struct sx_mutable *sxm, const void *data, size_t size,
						struct sx_node *next);

/* sxm_add_list • creates a new list node with the given data */
/*	returns the newly created node, or 0 on error */
struct sx_node *
sxm_add_list(struct sx_mutable *sxm, struct sx_node *data,
						struct sx_node *next);

/* sxm_init • initialisation of a struct sx_mutable */
/*	returns 0 on success, -1 on error */
int
sxm_init(struct sx_mutable *sxm, size_t dunit, size_t nunit);

/* sxm_release • release internal memory of a struct sx_mutable */
/*	if keep is non-NULL, the internal struct sexp is copied into it
 *	    instead of being released */
void
sxm_release(struct sx_mutable *sxm, struct sexp *keep);



/*********************************
 * S-EXPRESSION PARSER FUNCTIONS *
 *********************************/

#ifndef WITHOUT_SX_PARSER

/* sxp_file_to_sx • reads a file into a temporary sx_parser and fills a sx */
/*	returns 0 on succes, -1 on error */
int
sxp_file_to_sx(struct sexp *out, FILE *in, size_t readsize,
						size_t dunit, size_t nunit);

/* sxp_file_to_sxm • reads a file into a temporary sx_parser and fills a sxm */
/*	returns 0 on succes, -1 on error */
int
sxp_file_to_sxm(struct sx_mutable *out, FILE *in, size_t readsize,
						size_t dunit, size_t nunit);

/* sxp_init • initialisation a struct sx_parser */
/*	returns 0 on succes, -1 on error */
int
sxp_init(struct sx_parser *parser, size_t dunit, size_t nunit);

/* sxp_parse • feeds data into the parser */
/*	returns 0 on succes, -1 on error */
int
sxp_parse(struct sx_parser *parser, const void *data, size_t size);

/* sxp_readfile • feeds data read from a file into the parser */
/*	returns 0 on succes, -1 on error */
int
sxp_readfile(struct sx_parser *parser, FILE *in, size_t bufsize);

/* sxp_release • release of internal memory of a struct sx_parser */
/*	if keep_sxm is non-NULL, the internal struct sx_mutable is copied into
 *	    it instead of being released.
 *	if keep_sxm is NULL and keep_sx is non-NULL, the internal struct sexp
 *	    is copied into *keep_sx and the rest is released. */
void
sxp_release(struct sx_parser *parser, struct sx_mutable *keep_sxm,
							struct sexp *keep_sx);
#endif /* ndef WITHOUT_SX_PARSER */
#endif /* ndef WITHOUT_SX_MUTABLE */

#endif /* ndef LITHIUM_CSEXP_H */

/* vim: set filetype=c: */
