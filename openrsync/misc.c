/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2005,2006 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "config.h"

#include <sys/stat.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#if HAVE_ERR
# include <err.h>
#endif

#include "extern.h"

/* 
 * Function to assist building execv() arguments.
 */
void
addargs(arglist *args, const char *fmt, ...)
{
	va_list	 	 ap;
	char		*cp;
	unsigned int	 nalloc;
	int	 	 r;

	va_start(ap, fmt);
	r = vasprintf(&cp, fmt, ap);
	va_end(ap);
	if (r == -1)
		err(ERR_NOMEM, "addargs: argument too long");

	nalloc = args->nalloc;
	if (args->list == NULL) {
		nalloc = 32;
		args->num = 0;
	} else if (args->num+2 >= nalloc)
		nalloc *= 2;

	args->list = recallocarray(args->list, args->nalloc, nalloc,
	    sizeof(char *));
	if (!args->list)
		err(ERR_NOMEM, NULL);
	args->nalloc = nalloc;
	args->list[args->num++] = cp;
	args->list[args->num] = NULL;
}

/*
 * Only valid until the next call to addargs!
 */
const char *
getarg(arglist *args, size_t idx)
{

	if (args->list == NULL || args->num < idx)
		return NULL;
	return args->list[idx];
}

void
freeargs(arglist *args)
{
	unsigned int	 i;

	if (args->list != NULL) {
		for (i = 0; i < args->num; i++)
			free(args->list[i]);
		free(args->list);
		args->nalloc = args->num = 0;
		args->list = NULL;
	}
}

/*
 * The name is just used for diagnostic output.
 *
 * Returns 0 if the file did not pass strict mode verification, 1 if it
 * successfully passed.
 */
int
check_file_mode(const char *name, int fd)
{
	struct stat sb;

	if (fstat(fd, &sb) == -1) {
		ERR("%s: fstat", name);
		return 0;
	}

	if ((sb.st_mode & S_IRWXO) != 0) {
		ERRX("%s: strict mode violation (other permission bits set)",
		    name);
		return 0;
	}

	if (geteuid() == 0 && sb.st_uid != 0) {
		ERRX("%s: strict mode violation (root process, file not owned by root)",
		    name);
		return 0;
	}

	return 1;
}
