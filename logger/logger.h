/*
    logger.h -- logging

    Copyright (C) 2003-2004 Guus Sliepen <guus@tinc-vpn.org>

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

#ifndef __LOGGER_H__
#define __LOGGER_H__

typedef enum logger_level {
	LOGGER_LEVEL_NONE,
	LOGGER_LEVEL_NOTICE,
	LOGGER_LEVEL_WARNING,
	LOGGER_LEVEL_ERROR,
	LOGGER_LEVEL_DEBUG,
} logger_level_t;

typedef enum logger_mode {
	LOGGER_MODE_NULL,
	LOGGER_MODE_STDERR,
	LOGGER_MODE_FILE,
	LOGGER_MODE_SYSLOG,
} logger_mode_t;

extern bool logger_init(const char *, logger_mode_t);
extern bool logger_exit(void);
extern void logger(int, const char *, ...) __attribute__ ((__format__(printf, 2, 3)));

#endif
