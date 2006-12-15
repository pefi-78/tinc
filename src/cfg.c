/*
    cfg.c -- cfguration code

    Copyright (C) 1998 Robert van der Meulen
                  1998-2004 Ivo Timmermans <ivo@tinc-vpn.org>
                  2000-2004 Guus Sliepen <guus@tinc-vpn.org>
		  2000 Cris van Pelt <tribbel@arise.dhs.org>

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

#include "cfg/cfg.h"
#include "support/avl.h"
#include "support/xalloc.h"

static int cfg_compare(const cfg_t *a, const cfg_t *b) {
	return strcasecmp(a->variable, b->variable) ?: (a->line - b->line) ?: strcmp(a->file, b->file);
}

avl_tree_t *cfg_tree_new(void) {
	return avl_tree_new((avl_compare_t)cfg_compare, (avl_action_t)cfg_free);
}

void cfg_tree_del(avl_tree_t *cfgs) {
	avl_tree_del(cfgs);
}

cfg_t *cfg_new(void) {
	cfg_t *cfg;

	return clear(new(cfg));
}

void cfg_free(cfg_t *cfg) {
	replace(cfg->variable, NULL);
	replace(cfg->value, NULL);
	replace(cfg->file, NULL);
	free(cfg);
}

void cfg_add(avl_tree_t *cfgs, cfg_t *cfg) {
	avl_add(cfgs, cfg);
}

cfg_t *cfg_get(const avl_tree_t *cfgs, char *variable) {
	cfg_t search, *cfg;

	search.variable = variable;
	search.file = "";
	search.line = 0;

	cfg = avl_get_closest_greater(cfgs, &search);

	if(!cfg || strcasecmp(cfg->variable, variable))
		return NULL;

	return cfg;
}

cfg_t *cfg_get_next(const avl_tree_t *cfgs, const cfg_t *cfg) {
	avl_node_t *avl;
	cfg_t *next;

	avl = avl_get_node(cfgs, cfg);

	if(avl && avl->next) {
		next = avl->next->data;

		if(!strcasecmp(next->variable, cfg->variable))
			return next;
	}

	return NULL;
}

bool cfg_bool(const cfg_t *cfg, const bool def, bool *result) {
	if(!cfg) {
		*result = def;
		return true;
	}

	if(!strcasecmp(cfg->value, "yes")) {
		*result = true;
		return true;
	} else if(!strcasecmp(cfg->value, "no")) {
		*result = false;
		return true;
	}

	logger(LOG_ERR, _("cfg: \"yes\" or \"no\" expected for configuration variable %s in %s line %d"),
			cfg->variable, cfg->file, cfg->line);

	return false;
}

bool cfg_int(const cfg_t *cfg, const int def, int *result) {
	if(!cfg) {
		*result = def;
		return true;
	}

	if(sscanf(cfg->value, "%d", result) == 1)
		return true;

	logger(LOG_ERR, _("cfg: integer expected for configuration variable %s in %s line %d"),
		   cfg->variable, cfg->file, cfg->line);

	return false;
}

bool cfg_string(const cfg_t *cfg, const char *def, char **result) {
	if(!cfg) {
		*result = def ? xstrdup(def) : NULL;
		return true;
	}

	*result = xstrdup(cfg->value);

	return true;
}

bool cfg_choice(const cfg_t *cfg, const cfg_choice_t *choice, const int def, int *result) {
	int i;
	
	if(!cfg) {
		*result = def;
		return true;
	}

	for(i = 0; choice[i].key; i++) {
		if(!strcasecmp(cfg->variable, choice[i].key)) {
			*result = choice[i].value;
			return true;
		}
	}

	logger(LOG_ERR, _("cfg: invalid choice for configuration variable %s in %s line %d"), 
			cfg->variable, cfg->file, cfg->line);

	return false;
}	

bool cfg_period(const cfg_t *cfg, const int def, int *result) {
	char unit;
	
	if(!cfg) {
		*result = def;
		return true;
	}

	if(sscanf(cfg->value, "%d%c", result, &unit) == 2) {
		switch(unit) {
			case 's':
				break;
			case 'm':
				*result *= 60;
				break;
			case 'h':
				*result *= 60 * 60;
				break;
			case 'd':
				*result *= 60 * 60 * 24;
				break;
			case 'W':
				*result *= 60 * 60 * 24 * 7;
				break;
			case 'M':
				*result *= 60 * 60 * 24 * 30;
				break;
			case 'Y':
				*result *= 60 * 60 * 24 * 365;
				break;
			default:
				logger(LOG_ERR, _("cfg: invalid period for configuration variable %s in %s line %d"),
						cfg->variable, cfg->file, cfg->line);
				return false;
		}
		return true;
	}

	if(sscanf(cfg->value, "%d", result) == 1)
		return true;

	logger(LOG_ERR, _("cfg: period expected for configuration variable %s in %s line %d"),
			cfg->variable, cfg->file, cfg->line);

	return false;
}

static char *readline(FILE *fp, char **buf, size_t *buflen) {
	char *newline = NULL;
	char *p;
	char *line;					/* The array that contains everything that has been read so far */
	char *idx;					/* Read into this pointer, which points to an offset within line */
	size_t size, newsize;				/* The size of the current array pointed to by line */
	size_t maxlen;					/* Maximum number of characters that may be read with fgets.  This is newsize - oldsize. */

	if(feof(fp))
		return NULL;

	if(buf && buflen) {
		size = *buflen;
		line = *buf;
	} else {
		dim(line, size = 100);
	}

	maxlen = size;
	idx = line;
	*idx = 0;

	for(;;) {
		errno = 0;
		p = fgets(idx, maxlen, fp);

		if(!p) {
			if(feof(fp))
				break;

			logger(LOG_ERR, _("cfg: error while reading: %s"), strerror(errno));
			free(line);
			return NULL;
		}

		newline = strchr(p, '\n');

		if(!newline) {
			idx = &line[size - 1];
			maxlen = size + 1;
			redim(line, size *= 2);
		} else {
			*newline = '\0';
			break;
		}
	}

	if(buf && buflen) {
		*buflen = size;
		*buf = line;
	}

	return line;
}

bool cfg_read_file(avl_tree_t *cfgs, const char *fname) {
	FILE *fp;
	char *buffer, *line;
	char *variable, *value;
	int lineno = 0;
	int len;
	bool result = false;
	bool ignore = false;
	cfg_t *cfg;
	size_t bufsize;

	fp = fopen(fname, "r");

	if(!fp) {
		logger(LOG_ERR, _("cfg: error opening %s: %s"), fname, strerror(errno));
		return false;
	}

	dim(buffer, bufsize = 100);

	for(;;) {
		line = readline(fp, &buffer, &bufsize);

		if(!line)
			break;

		if(feof(fp)) {
			result = true;
			break;
		}

		lineno++;

		if(!*line || *line == '#')
			continue;

		if(ignore) {
			if(!strncmp(line, "-----END", 8))
				ignore = false;
			continue;
		}
		
		if(!strncmp(line, "-----BEGIN", 10)) {
			ignore = true;
			continue;
		}

		variable = value = line;

		len = strcspn(value, "\t =");
		value += len;
		value += strspn(value, "\t ");
		if(*value == '=') {
			value++;
			value += strspn(value, "\t ");
		}
		variable[len] = '\0';

		if(!*value) {
			logger(LOG_ERR, _("cfg: no value for variable %s on line %d while reading cfg file %s"),
					variable, lineno, fname);
			break;
		}

		cfg = cfg_new();
		replace(cfg->variable, variable);
		replace(cfg->value, value);
		replace(cfg->file, fname);
		cfg->line = lineno;

		cfg_add(cfgs, cfg);
	}

	free(buffer);
	fclose(fp);

	return result;
}
