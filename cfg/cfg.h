/*
    conf.h -- header for conf.c

    Copyright (C) 1998-2004 Ivo Timmermans <ivo@tinc-vpn.org>
                  2000-2004 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __TINC_CONF_H__
#define __TINC_CONF_H__

#include "support/avl.h"

typedef struct cfg {
	char *variable;
	char *value;
	char *file;
	int line;
} cfg_t;

typedef struct cfg_choice {
	char *key;
	int value;
} cfg_choice_t;

extern avl_tree_t *cfgs;

extern avl_tree_t *cfg_tree_new(void);
extern void cfg_tree_free(avl_tree_t *);
extern cfg_t *cfg_new(void) __attribute__ ((__malloc__));
extern void cfg_free(cfg_t *);
extern void cfg_add(avl_tree_t *, cfg_t *);
extern void cfg_del(avl_tree_t *, cfg_t *);
extern cfg_t *cfg_get(const avl_tree_t *, char *);
extern cfg_t *cfg_get_next(const avl_tree_t *, const cfg_t *);
extern bool cfg_bool(const cfg_t *, const bool, bool *);
extern bool cfg_int(const cfg_t *, const int, int *);
extern bool cfg_string(const cfg_t *, const char *, char **);
extern bool cfg_choice(const cfg_t *, const cfg_choice_t *, const int, int *);
extern bool cfg_period(const cfg_t *, const int, int *);
#define cfg_get_bool(tree, var, def, result) cfg_bool(cfg_get(tree, var), def, result)
#define cfg_get_int(tree, var, def, result) cfg_int(cfg_get(tree, var), def, result)
#define cfg_get_string(tree, var, def, result) cfg_string(cfg_get(tree, var), def, result)
#define cfg_get_choice(tree, var, choice, def, result) cfg_choice(cfg_get(tree, var), choice, def, (int *)result)
#define cfg_get_period(tree, var, def, result) cfg_period(cfg_get(tree, var), def, (int *)result)

extern bool cfg_read_file(avl_tree_t *, const char *);

#endif
