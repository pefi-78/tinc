/*
    tincd.h -- tinc specific global variables and functions

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

    $Id
*/

#ifndef __TINCD_H__
#define __TINCD_H__

#include "support/avl.h"

extern char *tinc_confbase;	
extern char *tinc_netname;	
extern char *tinc_identname;	
extern char *tinc_pidfilename;
extern char *tinc_logfilename;
extern char *tinc_cfgfilename;

extern bool tinc_use_logfile;

extern int tinc_argc;
extern char **tinc_argv;
extern avl_tree_t *tinc_cfg;

extern bool remove_pid(const char *pidfilename);

#endif
