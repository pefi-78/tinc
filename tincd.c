/*
    tincd.c -- the main file for tincd

    Copyright (C) 2000-2004 Guus Sliepen <guus@tinc-vpn.org>

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

#include <getopt.h>

#include "cfg/cfg.h"
#include "fd/event.h"
#include "fd/fd.h"
#include "logger/logger.h"
#include "support/avl.h"
#include "support/sockaddr.h"
#include "support/xalloc.h"
#include "tnl/tnl.h"
#include "vnd/vnd.h"

static bool show_help = false;
static bool show_version = false;
static int kill_tincd = 0;
static bool bypass_security = false;
static bool do_mlock = false;
static bool use_logfile = false;
static bool do_detach = true;
static int debug_level = 1;

static char *confbase = NULL;	
static char *identname = NULL;	
static char *pidfilename = NULL;
static char *logfilename = NULL;
static char *cfgfilename = NULL;

int tinc_argc;
char **tinc_argv;
cfg_tree_t tinc_cfg;

static struct option const long_options[] = {
	{"config", required_argument, NULL, 'c'},
	{"kill", optional_argument, NULL, 'k'},
	{"net", required_argument, NULL, 'n'},
	{"help", no_argument, NULL, 1},
	{"version", no_argument, NULL, 2},
	{"no-detach", no_argument, NULL, 'D'},
	{"debug", optional_argument, NULL, 'd'},
	{"bypass-security", no_argument, NULL, 3},
	{"mlock", no_argument, NULL, 'L'},
	{"logfile", optional_argument, NULL, 4},
	{"pidfile", required_argument, NULL, 5},
	{NULL, 0, NULL, 0}
};

#ifdef HAVE_MINGW
static struct WSAData wsa_state;
#endif

static void usage(bool status) {
	if(status)
		fprintf(stderr, _("Try `%s --help\' for more information.\n"), tinc_argv[0]);
	else {
		printf(_("Usage: %s [option]...\n\n"), tinc_argv[0]);
		printf(_("  -c, --config=DIR           Read configuration options from DIR.\n"
				"  -D, --no-detach            Don't fork and detach.\n"
				"  -d, --debug[=LEVEL]        Increase debug level or set it to LEVEL.\n"
				"  -k, --kill[=SIGNAL]        Attempt to kill a running tincd and exit.\n"
				"  -n, --net=NETNAME          Connect to net NETNAME.\n"
				"  -L, --mlock                Lock tinc into main memory.\n"
				"      --logfile[=FILENAME]   Write log entries to a logfile.\n"
				"      --pidfile=FILENAME     Write PID to FILENAME.\n"
				"      --help                 Display this help and exit.\n"
				"      --version              Output version information and exit.\n\n"));
		printf(_("Report bugs to tinc@tinc-vpn.org.\n"));
	}
}

static bool parse_options(int argc, char **argv) {
	int result;
	int option_index = 0;

	while((result = getopt_long(argc, argv, "c:DLd::k::n:", long_options, &option_index)) != EOF) {
		switch (result) {
			case 0:
				break;

			case 'c': /* --config */
				confbase = xstrdup(optarg);
				break;

			case 'D': /* --no-detach */
				do_detach = false;
				break;

			case 'L': /* --mlock */
				do_mlock = true;
				break;

			case 'd': /* --debug */
				if(optarg)
					debug_level = atoi(optarg);
				else
					debug_level++;
				break;

			case 'k': /* --kill */
#ifndef HAVE_MINGW
				if(optarg) {
					if(!strcasecmp(optarg, "HUP"))
						kill_tincd = SIGHUP;
					else if(!strcasecmp(optarg, "TERM"))
						kill_tincd = SIGTERM;
					else if(!strcasecmp(optarg, "KILL"))
						kill_tincd = SIGKILL;
					else if(!strcasecmp(optarg, "USR1"))
						kill_tincd = SIGUSR1;
					else if(!strcasecmp(optarg, "USR2"))
						kill_tincd = SIGUSR2;
					else if(!strcasecmp(optarg, "WINCH"))
						kill_tincd = SIGWINCH;
					else if(!strcasecmp(optarg, "INT"))
						kill_tincd = SIGINT;
					else if(!strcasecmp(optarg, "ALRM"))
						kill_tincd = SIGALRM;
					else {
						kill_tincd = atoi(optarg);

						if(!kill_tincd) {
							fprintf(stderr, _("Invalid argument `%s'; SIGNAL must be a number or one of HUP, TERM, KILL, USR1, USR2, WINCH, INT or ALRM.\n"),
									optarg);
							usage(true);
							return false;
						}
					}
				} else
					kill_tincd = SIGTERM;
#else
					kill_tincd = 1;
#endif
				break;

			case 'n': /* --net */
				netname = xstrdup(optarg);
				break;

			case 1:	/* --help */
				show_help = true;
				break;

			case 2: /* --version */
				show_version = true;
				break;

			case 3: /* --bypass-security */
				bypass_security = true;
				break;

			case 4: /* --logfile */
				use_logfile = true;
				if(optarg)
					logfilename = xstrdup(optarg);
				break;

			case 5: /* --pidfile */
				pidfilename = xstrdup(optarg);
				break;

			case '?':
				usage(true);
				return false;

			default:
				break;
		}
	}

	return true;
}

static void make_names(void)
{
#ifdef HAVE_MINGW
	HKEY key;
	char installdir[1024] = "";
	long len = sizeof(installdir);
#endif

	if(netname)
		asprintf(&identname, "tinc.%s", netname);
	else
		identname = xstrdup("tinc");

#ifdef HAVE_MINGW
	if(!RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\tinc", 0, KEY_READ, &key)) {
		if(!RegQueryValueEx(key, NULL, 0, 0, installdir, &len)) {
			if(!logfilename)
				asprintf(&logfilename, "%s/log/%s.log", identname);
			if(!confbase) {
				if(netname)
					asprintf(&confbase, "%s/%s", installdir, netname);
				else
					asprintf(&confbase, "%s", installdir);
			}
		}
		RegCloseKey(key);
		if(*installdir)
			return;
	}
#endif

	if(!pidfilename)
		asprintf(&pidfilename, LOCALSTATEDIR "/run/%s.pid", identname);

	if(!logfilename)
		asprintf(&logfilename, LOCALSTATEDIR "/log/%s.log", identname);

	if(!confbase) {
		if(netname)
			asprintf(&confbase, CONFDIR "/tinc/%s", netname);
		else
			asprintf(&confbase, CONFDIR "/tinc");
	}

	asprintf(&cfgfilename, "%s/tinc.conf", confbase);
}

int main(int argc, char **argv) {
	tinc_argc = argc;
	tinc_argv = argv;

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

	if(!parse_options(argc, argv))
		return 1;
	
	make_names();

	if(show_version) {
		printf(_("%s version %s (built %s %s, protocol %d)\n"), PACKAGE,
			   VERSION, __DATE__, __TIME__, PROT_CURRENT);
		printf(_("Copyright (C) 1998-2004 Ivo Timmermans, Guus Sliepen and others.\n"
				"See the AUTHORS file for a complete list.\n\n"
				"tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n"
				"and you are welcome to redistribute it under certain conditions;\n"
				"see the file COPYING for details.\n"));

		return 0;
	}

	if(show_help) {
		usage(false);
		return 0;
	}

	if(kill_tincd)
		return !kill_other(kill_tincd);

	openlogger("tinc", use_logfile?LOGMODE_FILE:LOGMODE_STDERR);

	/* Lock all pages into memory if requested */

	if(do_mlock)
#ifdef HAVE_MLOCKALL
		if(mlockall(MCL_CURRENT | MCL_FUTURE)) {
			logger(LOG_ERR, _("System call `%s' failed: %s"), "mlockall",
				   strerror(errno));
#else
	{
		logger(LOG_ERR, _("mlockall() not supported on this platform!"));
#endif
		return -1;
	}

	tinc_cfg = cfg_tree_new();

	asprintf(cfgfilename, "%s/tinc.conf", confbase);
	
	if(!cfg_read_file(tinc_cfg, cfgfilename))
		return 1;

#ifdef HAVE_MINGW
	if(WSAStartup(MAKEWORD(2, 2), &wsa_state)) {
		logger(LOG_ERR, _("System call `%s' failed: %s"), "WSAStartup", winerror(GetLastError()));
		return 1;
	}
#endif

	if(do_detach && !detach())
		return 1;

	if(!fd_init() || !tnl_init() || !rt_init())
		return 1;

	fd_run();

	rt_exit();
	tnl_exit();
	fd_exit();
end:
	logger(LOG_NOTICE, _("Terminating"));

#ifndef HAVE_MINGW
	remove_pid(pidfilename);
#endif

	logger_exit();
	
	return 0;
}
