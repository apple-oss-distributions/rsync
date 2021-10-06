/* 
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) 2002 by Martin Pool
   
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
*/

/**
 * @file syscall.c
 *
 * Syscall wrappers to ensure that nothing gets done in dry_run mode
 * and to handle system peculiarities.
 **/

#include "rsync.h"

#ifdef HAVE_COPYFILE_H
#include <libgen.h>
#include <copyfile.h>
#endif

extern int dry_run;
extern int read_only;
extern int list_only;
extern int preserve_perms;
#ifdef EA_SUPPORT
extern int extended_attributes;
#endif

#define RETURN_ERROR_IF(x,e) \
	do { \
		if (x) { \
			errno = (e); \
			return -1; \
		} \
	} while (0)

#define RETURN_ERROR_IF_RO_OR_LO RETURN_ERROR_IF(read_only || list_only, EROFS)

int do_unlink(char *fname)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
#ifdef HAVE_COPYFILE
	if (extended_attributes && !strncmp("._", basename(fname), 2))
	{
	    int ret;
	    ret = unlink(fname);

	    if(ret == -1 && errno != ENOENT)
		return -1;
	    else
		return 0;
	}
#endif
	return unlink(fname);
}

int do_symlink(char *fname1, char *fname2)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return symlink(fname1, fname2);
}

#if HAVE_LINK
int do_link(char *fname1, char *fname2)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return link(fname1, fname2);
}
#endif

int do_lchown(const char *path, uid_t owner, gid_t group)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return lchown(path, owner, group);
}

#if HAVE_MKNOD
int do_mknod(char *pathname, mode_t mode, dev_t dev)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return mknod(pathname, mode, dev);
}
#endif

int do_rmdir(char *pathname)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	return rmdir(pathname);
}

int do_open(char *pathname, int flags, mode_t mode)
{
	if (flags != O_RDONLY) {
		RETURN_ERROR_IF(dry_run, 0);
		RETURN_ERROR_IF_RO_OR_LO;
	}

	return open(pathname, flags | O_BINARY, mode);
}

#if HAVE_CHMOD
int do_chmod(const char *path, mode_t mode)
{
	int code;
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	code = chmod(path, mode);
	if (code != 0 && preserve_perms)
	    return code;
	return 0;
}
#endif

int do_rename(char *fname1, char *fname2)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
#ifdef HAVE_COPYFILE
	if(extended_attributes)
	{
	    char dst_fname[MAXPATHLEN];
	    if(!strncmp(basename(fname1), ".._", 3))
	    {
		snprintf(dst_fname, MAXPATHLEN, "%s/%s", dirname(fname2), basename(fname2) + 2);
		if(copyfile(fname1, dst_fname, 0,
		    COPYFILE_UNPACK | COPYFILE_METADATA) == 0)
		return unlink(fname1);
	    }
	}
#endif
	return rename(fname1, fname2);
}


void trim_trailing_slashes(char *name)
{
	int l;
	/* Some BSD systems cannot make a directory if the name
	 * contains a trailing slash.
	 * <http://www.opensource.apple.com/bugs/X/BSD%20Kernel/2734739.html> */
	
	/* Don't change empty string; and also we can't improve on
	 * "/" */
	
	l = strlen(name);
	while (l > 1) {
		if (name[--l] != '/')
			break;
		name[l] = '\0';
	}
}


int do_mkdir(char *fname, mode_t mode)
{
	if (dry_run) return 0;
	RETURN_ERROR_IF_RO_OR_LO;
	trim_trailing_slashes(fname);	
	return mkdir(fname, mode);
}


/* like mkstemp but forces permissions */
int do_mkstemp(char *template, mode_t perms)
{
	RETURN_ERROR_IF(dry_run, 0);
	RETURN_ERROR_IF(read_only, EROFS);

#if HAVE_SECURE_MKSTEMP && HAVE_FCHMOD && (!HAVE_OPEN64 || HAVE_MKSTEMP64)
	{
		int fd = mkstemp(template);
		if (fd == -1)
			return -1;
		if (fchmod(fd, perms) != 0 && preserve_perms) {
			int errno_save = errno;
			close(fd);
			unlink(template);
			errno = errno_save;
			return -1;
		}
		return fd;
	}
#else
	if (!mktemp(template))
		return -1;
	return do_open(template, O_RDWR|O_EXCL|O_CREAT, perms);
#endif
}

int do_stat(const char *fname, STRUCT_STAT *st)
{
#if HAVE_OFF64_T
	return stat64(fname, st);
#else
	return stat(fname, st);
#endif
}

#if SUPPORT_LINKS
int do_lstat(const char *fname, STRUCT_STAT *st)
{
#if HAVE_OFF64_T
	return lstat64(fname, st);
#else
	return lstat(fname, st);
#endif
}
#endif

int do_fstat(int fd, STRUCT_STAT *st)
{
#if HAVE_OFF64_T
	return fstat64(fd, st);
#else
	return fstat(fd, st);
#endif
}

OFF_T do_lseek(int fd, OFF_T offset, int whence)
{
#if HAVE_OFF64_T
	off64_t lseek64();
	return lseek64(fd, offset, whence);
#else
	return lseek(fd, offset, whence);
#endif
}

#ifdef USE_MMAP
void *do_mmap(void *start, int len, int prot, int flags, int fd, OFF_T offset)
{
#if HAVE_OFF64_T
	return mmap64(start, len, prot, flags, fd, offset);
#else
	return mmap(start, len, prot, flags, fd, offset);
#endif
}
#endif

char *d_name(struct dirent *di)
{
#if HAVE_BROKEN_READDIR
	return (di->d_name - 2);
#else
	return di->d_name;
#endif
}
