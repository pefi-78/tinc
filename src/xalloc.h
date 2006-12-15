/*
    xalloc.h -- safe memory allocation functions

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

#ifndef __XALLOC_H__
#define __XALLOC_H__

#define new(object) ({(object) = xmalloc(sizeof *(object));})
#define dim(object, count) ({(object) = xmalloc(sizeof *(object) * (count));})
#define redim(object, count) ({(object) = xrealloc((object), sizeof *(object) * (count));})
#define copy(object) ({typeof(object) _copy; *(_copy = xmalloc(sizeof *(object))) = *(object); _copy;})
#define clear(object) ({memset((object), 0, sizeof *(object));})
#define replace(string, replacement) ({if(string) free(string); (string) = (replacement) ? xstrdup(replacement) : NULL;})

void *xmalloc(size_t n) __attribute__ ((__malloc__));
void *xrealloc(void *p, size_t n) __attribute__ ((__malloc__));
char *xstrdup(const char *s) __attribute__ ((__malloc__));

#endif
