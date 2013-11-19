/*
 * This file is part of ltrace.
 * Copyright (C) 2012 Petr Machata, Red Hat Inc.
 * Copyright (C) 2003,2009 Juan Cespedes
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>
#include <stdarg.h>

#include <stdio.h>



#define ABORT(msg...)            {       \
	fprintf(options.output, msg);        \
	exit(-1);  }

// like an assert except that it always fires
#define EXITIF(x) do { \
	if (x) { \
		fprintf(options.output, "Fatal error in %s [%s:%d]\n", __FUNCTION__, __FILE__, __LINE__); \
		exit(1); \
	} \
	} while(0)

/* off set to get the RAX register */
#define ORIG_RAX 15
#define ORIG_XAX (8 * ORIG_RAX)

#define debug(level, expr...) debug_(level, __FILE__, __LINE__, expr)

struct options_t {
	FILE *output;   /* output to a specific file */
	int debug;      /* debug */
};

struct options_t options;

/* debug levels:
 */
enum {
	LOG_INFO    = 010,
	LOG_MAPPING = 020,
	LOG_EVENT = 040,
};


void debug_(int level, const char *file, int line, const char *fmt, ...)
		__attribute__((format(printf,4,5)));

void
debug_(int level, const char *file, int line, const char *fmt, ...){

	if (!(options.debug & level)) {
		return;
	}

	fprintf(options.output, "DEBUG: %s:%d: ", file, line);

        va_list args;
        va_start(args, fmt);
        vfprintf(options.output, fmt, args);
        fprintf(options.output, "\n");
        va_end(args);

	fflush(options.output);
	return;
}

#endif
