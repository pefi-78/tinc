/*
    xalloc.c -- safe memory allocation functions

    Copyright (C) 2003-2004 Guus Sliepen <guus@tinc-vpn.org>,

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

    $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xalloc.h"

static void xalloc_fail(void) {
	fprintf(stderr, "Memory exhausted\n");
	exit(1);
}

void (*xalloc_fail_func)(void) = xalloc_fail;

void *xmalloc(size_t n) {
	void *p;

	p = malloc(n);

	if(!p)
		xalloc_fail_func();

	return p;
}

void *xrealloc(void *p, size_t n) {
	p = realloc(p, n);

	if(!p)
		xalloc_fail_func();

	return p;
}

void *xcalloc(size_t n, size_t s) {
	void *p;

	p = calloc(n, s);

	if(!p)
		xalloc_fail_func();

	return p;
}

char *xstrdup(const char *s) {
	char *p;

	p = strdup(s);

	if(!p)
		xalloc_fail_func();

	return p;
}

