/*
    logger.c -- logging

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

#include "system.h"

#include "logger/logger.h"

logger_level_t logger_level = LOGGER_LEVEL_NONE;

static logger_mode_t logger_mode = LOGGER_MODE_STDERR;
static pid_t logger_pid;
char *logger_filename;
static FILE *logger_file = NULL;
#ifdef HAVE_MINGW
static HANDLE logger_handle = NULL;
#endif
static const char *logger_ident = NULL;

bool logger_init(const char *ident, logger_mode_t mode) {
	logger_ident = ident;
	logger_mode = mode;
	
	switch(mode) {
		case LOGGER_MODE_STDERR:
			logger_pid = getpid();
			break;
		case LOGGER_MODE_FILE:
			logger_pid = getpid();
			logger_file = fopen(logger_filename, "a");
			if(!logger_file)
				logger_mode = LOGGER_MODE_NULL;
			break;
		case LOGGER_MODE_SYSLOG:
#ifdef HAVE_MINGW
			logger_handle = RegisterEventSource(NULL, logger_ident);
			if(!logger_handle)
				logger_mode = LOGGER_MODE_NULL;
			break;
#else
#ifdef HAVE_SYSLOG_H
			openlog(logger_ident, LOG_CONS | LOG_PID, LOG_DAEMON);
			break;
#endif
#endif
		case LOGGER_MODE_NULL:
			break;
	}

	return true;
}

bool logger_exit(void) {
	switch(logger_mode) {
		case LOGGER_MODE_FILE:
			fclose(logger_file);
			break;
		case LOGGER_MODE_SYSLOG:
#ifdef HAVE_MINGW
			DeregisterEventSource(logger_handle);
			break;
#else
#ifdef HAVE_SYSLOG_H
			closelog();
			break;
#endif
#endif
		case LOGGER_MODE_NULL:
		case LOGGER_MODE_STDERR:
			break;
			break;
	}

	return true;
}

void logger(int priority, const char *format, ...) {
	va_list ap;

	va_start(ap, format);

	switch(logger_mode) {
		case LOGGER_MODE_STDERR:
			vfprintf(stderr, format, ap);
			fprintf(stderr, "\n");
			fflush(stderr);
			break;
		case LOGGER_MODE_FILE:
			fprintf(logger_file, "%ld %s[%ld]: ", time(NULL), logger_ident, (long)logger_pid);
			vfprintf(logger_file, format, ap);
			fprintf(logger_file, "\n");
			fflush(logger_file);
			break;
		case LOGGER_MODE_SYSLOG:
#ifdef HAVE_MINGW
			{
				char message[4096];
				char *messages[] = {message};
				vsnprintf(message, sizeof(message), format, ap);
				ReportEvent(logger_handle, priority, 0, 0, NULL, 1, 0, messages, NULL);
			}
#else
#ifdef HAVE_SYSLOG_H
#ifdef HAVE_VSYSLOG
			vsyslog(priority, format, ap);
#else
			{
				char message[4096];
				vsnprintf(message, sizeof(message), format, ap);
				syslog(priority, "%s", message);
			}
#endif
			break;
#endif
#endif
		case LOGGER_MODE_NULL:
			break;
	}

	va_end(ap);
}


