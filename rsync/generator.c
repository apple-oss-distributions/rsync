/* -*- c-file-style: "linux" -*-

   rsync -- fast file replication program

   Copyright (C) 1996-2000 by Andrew Tridgell
   Copyright (C) Paul Mackerras 1996
   Copyright (C) 2002 by Martin Pool <mbp@samba.org>

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

#include "rsync.h"

extern int verbose;
extern int dry_run;
extern int relative_paths;
extern int keep_dirlinks;
extern int preserve_links;
extern int am_root;
extern int preserve_devices;
extern int preserve_hard_links;
extern int preserve_perms;
extern int preserve_uid;
extern int preserve_gid;
extern int update_only;
extern int opt_ignore_existing;
extern int inplace;
extern int make_backups;
extern int csum_length;
extern int ignore_times;
extern int size_only;
extern int io_timeout;
extern int protocol_version;
extern int always_checksum;
extern char *partial_dir;
extern char *compare_dest;
extern int link_dest;
extern int whole_file;
extern int local_server;
extern int list_only;
extern int read_batch;
extern int only_existing;
extern int orig_umask;
extern int safe_symlinks;
extern unsigned int block_size;
#ifdef EA_SUPPORT
extern int extended_attributes;
#endif

extern struct exclude_list_struct server_exclude_list;


/* choose whether to skip a particular file */
static int skip_file(char *fname, struct file_struct *file, STRUCT_STAT *st)
{
	if (st->st_size != file->length)
		return 0;
	if (link_dest) {
		if (preserve_perms
		    && (st->st_mode & CHMOD_BITS) != (file->mode & CHMOD_BITS))
			return 0;

		if (am_root && preserve_uid && st->st_uid != file->uid)
			return 0;

		if (preserve_gid && file->gid != GID_NONE
		    && st->st_gid != file->gid)
			return 0;
	}

	/* if always checksum is set then we use the checksum instead
	   of the file time to determine whether to sync */
	if (always_checksum && S_ISREG(st->st_mode)) {
		char sum[MD4_SUM_LENGTH];
		file_checksum(fname,sum,st->st_size);
		return memcmp(sum, file->u.sum, protocol_version < 21 ? 2
							: MD4_SUM_LENGTH) == 0;
	}

	if (size_only)
		return 1;

	if (ignore_times)
		return 0;

	return cmp_modtime(st->st_mtime, file->modtime) == 0;
}


/*
 * NULL sum_struct means we have no checksums
 */
void write_sum_head(int f, struct sum_struct *sum)
{
	static struct sum_struct null_sum;

	if (sum == NULL)
		sum = &null_sum;

	write_int(f, sum->count);
	write_int(f, sum->blength);
	if (protocol_version >= 27)
		write_int(f, sum->s2length);
	write_int(f, sum->remainder);
}

/*
 * set (initialize) the size entries in the per-file sum_struct
 * calculating dynamic block and checksum sizes.
 *
 * This is only called from generate_and_send_sums() but is a separate
 * function to encapsulate the logic.
 *
 * The block size is a rounded square root of file length.
 *
 * The checksum size is determined according to:
 *     blocksum_bits = BLOCKSUM_EXP + 2*log2(file_len) - log2(block_len)
 * provided by Donovan Baarda which gives a probability of rsync
 * algorithm corrupting data and falling back using the whole md4
 * checksums.
 *
 * This might be made one of several selectable heuristics.
 */

static void sum_sizes_sqroot(struct sum_struct *sum, uint64 len)
{
	unsigned int blength;
	int s2length;
	uint32 c;
	uint64 l;

	if (block_size) {
		blength = block_size;
	} else if (len <= BLOCK_SIZE * BLOCK_SIZE) {
		blength = BLOCK_SIZE;
	} else {
		l = len;
		c = 1;
		while (l >>= 2) {
			c <<= 1;
		}
		blength = 0;
		do {
			blength |= c;
			if (len < (uint64)blength * blength)
				blength &= ~c;
			c >>= 1;
		} while (c >= 8);	/* round to multiple of 8 */
		blength = MAX(blength, BLOCK_SIZE);
	}

	if (protocol_version < 27) {
		s2length = csum_length;
	} else if (csum_length == SUM_LENGTH) {
		s2length = SUM_LENGTH;
	} else {
		int b = BLOCKSUM_BIAS;
		l = len;
		while (l >>= 1) {
			b += 2;
		}
		c = blength;
		while (c >>= 1 && b) {
			b--;
		}
		s2length = (b + 1 - 32 + 7) / 8; /* add a bit,
						  * subtract rollsum,
						  * round up
						  *    --optimize in compiler--
						  */
		s2length = MAX(s2length, csum_length);
		s2length = MIN(s2length, SUM_LENGTH);
	}

	sum->flength	= len;
	sum->blength	= blength;
	sum->s2length	= s2length;
	sum->count	= (len + (blength - 1)) / blength;
	sum->remainder	= (len % blength);

	if (sum->count && verbose > 2) {
		rprintf(FINFO, "count=%.0f rem=%u blength=%u s2length=%d flength=%.0f\n",
			(double)sum->count, sum->remainder, sum->blength,
			sum->s2length, (double)sum->flength);
	}
}


/*
 * Generate and send a stream of signatures/checksums that describe a buffer
 *
 * Generate approximately one checksum every block_len bytes.
 */
static void generate_and_send_sums(int fd, OFF_T len, int f_out, int f_copy)
{
	size_t i;
	struct map_struct *mapbuf;
	struct sum_struct sum;
	OFF_T offset = 0;

	sum_sizes_sqroot(&sum, len);

	if (len > 0)
		mapbuf = map_file(fd, len, MAX_MAP_SIZE, sum.blength);
	else
		mapbuf = NULL;

	write_sum_head(f_out, &sum);

	for (i = 0; i < sum.count; i++) {
		unsigned int n1 = MIN(len, sum.blength);
		char *map = map_ptr(mapbuf, offset, n1);
		uint32 sum1 = get_checksum1(map, n1);
		char sum2[SUM_LENGTH];

		if (f_copy >= 0)
			full_write(f_copy, map, n1);

		get_checksum2(map, n1, sum2);

		if (verbose > 3) {
			rprintf(FINFO,
				"chunk[%.0f] offset=%.0f len=%u sum1=%08lx\n",
				(double)i, (double)offset, n1,
				(unsigned long)sum1);
		}
		write_int(f_out, sum1);
		write_buf(f_out, sum2, sum.s2length);
		len -= n1;
		offset += n1;
	}

	if (mapbuf)
		unmap_file(mapbuf);
}



/*
 * Acts on file number @p i from @p flist, whose name is @p fname.
 *
 * First fixes up permissions, then generates checksums for the file.
 *
 * @note This comment was added later by mbp who was trying to work it
 * out.  It might be wrong.
 */
static void recv_generator(char *fname, struct file_struct *file, int i,
			   int f_out)
{
	int fd, f_copy;
	STRUCT_STAT st, partial_st;
	struct file_struct *back_file;
	int statret, stat_errno;
	char *fnamecmp, *partialptr, *backupptr;
	char fnamecmpbuf[MAXPATHLEN];

	if (list_only)
		return;

	if (verbose > 2)
		rprintf(FINFO, "recv_generator(%s,%d)\n", safe_fname(fname), i);

	if (server_exclude_list.head
	    && check_exclude(&server_exclude_list, fname,
			     S_ISDIR(file->mode)) < 0) {
		if (verbose) {
			rprintf(FINFO, "skipping server-excluded file \"%s\"\n",
				safe_fname(fname));
		}
		return;
	}

	if (dry_run > 1) {
		statret = -1;
		stat_errno = ENOENT;
	} else {
		statret = link_stat(fname, &st,
				    keep_dirlinks && S_ISDIR(file->mode));
		stat_errno = errno;
	}

	if (only_existing && statret == -1 && stat_errno == ENOENT) {
		/* we only want to update existing files */
		if (verbose > 1) {
			rprintf(FINFO, "not creating new file \"%s\"\n",
				safe_fname(fname));
		}
		return;
	}

	if (statret == 0 && !preserve_perms
	    && S_ISDIR(st.st_mode) == S_ISDIR(file->mode)) {
		/* if the file exists already and we aren't perserving
		 * permissions then act as though the remote end sent
		 * us the file permissions we already have */
		file->mode = (file->mode & ~CHMOD_BITS)
			   | (st.st_mode & CHMOD_BITS);
	}

	if (S_ISDIR(file->mode)) {
		/* The file to be received is a directory, so we need
		 * to prepare appropriately.  If there is already a
		 * file of that name and it is *not* a directory, then
		 * we need to delete it.  If it doesn't exist, then
		 * recursively create it. */

		if (dry_run)
			return; /* TODO: causes inaccuracies -- fix */
		if (statret == 0 && !S_ISDIR(st.st_mode)) {
			if (robust_unlink(fname) != 0) {
				rsyserr(FERROR, errno,
					"recv_generator: unlink %s to make room for directory",
					full_fname(fname));
				return;
			}
			statret = -1;
		}
		if (statret != 0 && do_mkdir(fname,file->mode) != 0 && errno != EEXIST) {
			if (!(relative_paths && errno == ENOENT
			    && create_directory_path(fname, orig_umask) == 0
			    && do_mkdir(fname, file->mode) == 0)) {
				rsyserr(FERROR, errno,
					"recv_generator: mkdir %s failed",
					full_fname(fname));
			}
		}
		/* f_out is set to -1 when doing final directory-permission
		 * and modification-time repair. */
		if (set_perms(fname, file, statret ? NULL : &st, 0)
		    && verbose && f_out != -1)
			rprintf(FINFO, "%s/\n", safe_fname(fname));
		return;
	}

	if (preserve_links && S_ISLNK(file->mode)) {
#if SUPPORT_LINKS
		char lnk[MAXPATHLEN];
		int l;

		if (safe_symlinks && unsafe_symlink(file->u.link, fname)) {
			if (verbose) {
				rprintf(FINFO, "ignoring unsafe symlink %s -> \"%s\"\n",
					full_fname(fname), file->u.link);
			}
			return;
		}
		if (statret == 0) {
			l = readlink(fname,lnk,MAXPATHLEN-1);
			if (l > 0) {
				lnk[l] = 0;
				/* A link already pointing to the
				 * right place -- no further action
				 * required. */
				if (strcmp(lnk,file->u.link) == 0) {
					set_perms(fname, file, &st,
						  PERMS_REPORT);
					return;
				}
			}
			/* Not a symlink, so delete whatever's
			 * already there and put a new symlink
			 * in place. */
			delete_file(fname);
		}
		if (do_symlink(file->u.link,fname) != 0) {
			rsyserr(FERROR, errno, "symlink %s -> \"%s\" failed",
				full_fname(fname), safe_fname(file->u.link));
		} else {
			set_perms(fname,file,NULL,0);
			if (verbose) {
				rprintf(FINFO, "%s -> %s\n", safe_fname(fname),
					safe_fname(file->u.link));
			}
		}
#endif
		return;
	}

#ifdef HAVE_MKNOD
	if (am_root && preserve_devices && IS_DEVICE(file->mode)) {
		if (statret != 0 ||
		    st.st_mode != file->mode ||
		    st.st_rdev != file->u.rdev) {
			delete_file(fname);
			if (verbose > 2) {
				rprintf(FINFO,"mknod(%s,0%o,0x%x)\n",
					safe_fname(fname),
					(int)file->mode, (int)file->u.rdev);
			}
			if (do_mknod(fname,file->mode,file->u.rdev) != 0) {
				rsyserr(FERROR, errno, "mknod %s failed",
					full_fname(fname));
			} else {
				set_perms(fname,file,NULL,0);
				if (verbose) {
					rprintf(FINFO, "%s\n",
						safe_fname(fname));
				}
			}
		} else {
			set_perms(fname, file, &st, PERMS_REPORT);
		}
		return;
	}
#endif

	if (preserve_hard_links && hard_link_check(file, HL_CHECK_MASTER))
		return;

	if (!S_ISREG(file->mode)) {
		rprintf(FINFO, "skipping non-regular file \"%s\"\n",
			safe_fname(fname));
		return;
	}

	fnamecmp = fname;

	if (statret == -1 && compare_dest != NULL) {
		/* try the file at compare_dest instead */
		pathjoin(fnamecmpbuf, sizeof fnamecmpbuf, compare_dest, fname);
		if (link_stat(fnamecmpbuf, &st, 0) == 0
		    && S_ISREG(st.st_mode)) {
#if HAVE_LINK
			if (link_dest && !dry_run) {
				if (do_link(fnamecmpbuf, fname) < 0) {
					if (verbose) {
						rsyserr(FINFO, errno,
							"link %s => %s",
							fnamecmpbuf,
							safe_fname(fname));
					}
					fnamecmp = fnamecmpbuf;
				}
			} else
#endif
				fnamecmp = fnamecmpbuf;
			statret = 0;
		}
	}

	if (statret == 0 && !S_ISREG(st.st_mode)) {
		if (delete_file(fname) != 0)
			return;
		statret = -1;
		stat_errno = ENOENT;
	}

	if (partial_dir && (partialptr = partial_dir_fname(fname))
	    && link_stat(partialptr, &partial_st, 0) == 0
	    && S_ISREG(partial_st.st_mode)) {
		if (statret == -1)
			goto prepare_to_open;
	} else
		partialptr = NULL;

	if (statret == -1) {
		if (preserve_hard_links && hard_link_check(file, HL_SKIP))
			return;
		if (stat_errno == ENOENT) {
			write_int(f_out,i);
			if (!dry_run && !read_batch)
				write_sum_head(f_out, NULL);
		} else if (verbose > 1) {
			rsyserr(FERROR, stat_errno,
				"recv_generator: failed to stat %s",
				full_fname(fname));
		}
		return;
	}

	if (opt_ignore_existing && fnamecmp == fname) {
		if (verbose > 1)
			rprintf(FINFO, "%s exists\n", safe_fname(fname));
		return;
	}

	if (update_only && fnamecmp == fname
	    && cmp_modtime(st.st_mtime, file->modtime) > 0) {
		if (verbose > 1)
			rprintf(FINFO, "%s is newer\n", safe_fname(fname));
		return;
	}

	if (skip_file(fnamecmp, file, &st)) {
		if (fnamecmp == fname)
			set_perms(fname, file, &st, PERMS_REPORT);
		return;
	}

prepare_to_open:
	if (dry_run || read_batch) {
		write_int(f_out,i);
		return;
	}

	if (whole_file > 0) {
		write_int(f_out,i);
		write_sum_head(f_out, NULL);
		return;
	}

	if (partialptr) {
		st = partial_st;
		fnamecmp = partialptr;
	}

	/* open the file */
	fd = do_open(fnamecmp, O_RDONLY, 0);

	if (fd == -1) {
		rsyserr(FERROR, errno, "failed to open %s, continuing",
			full_fname(fnamecmp));
	    pretend_missing:
		/* pretend the file didn't exist */
		if (preserve_hard_links && hard_link_check(file, HL_SKIP))
			return;
		write_int(f_out,i);
		write_sum_head(f_out, NULL);
		return;
	}

	if (inplace && make_backups) {
		if (!(backupptr = get_backup_name(fname))) {
			close(fd);
			return;
		}
		if (!(back_file = make_file(fname, NULL, NO_EXCLUDES))) {
			close(fd);
			goto pretend_missing;
		}
		if (robust_unlink(backupptr) && errno != ENOENT) {
			rsyserr(FERROR, errno, "unlink %s",
				full_fname(backupptr));
			free(back_file);
			close(fd);
			return;
		}
		if ((f_copy = do_open(backupptr,
		    O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0600)) < 0) {
			rsyserr(FERROR, errno, "open %s",
				full_fname(backupptr));
			free(back_file);
			close(fd);
			return;
		}
	} else {
		backupptr = NULL;
		back_file = NULL;
		f_copy = -1;
	}

	if (verbose > 3) {
		rprintf(FINFO, "gen mapped %s of size %.0f\n",
			safe_fname(fnamecmp), (double)st.st_size);
	}

	if (verbose > 2)
		rprintf(FINFO, "generating and sending sums for %d\n", i);

	write_int(f_out,i);
	generate_and_send_sums(fd, st.st_size, f_out, f_copy);

	if (f_copy >= 0) {
		close(f_copy);
		set_perms(backupptr, back_file, NULL, 0);
		if (verbose > 1)
			rprintf(FINFO, "backed up %s to %s\n", fname, backupptr);
		free(back_file);
	}

	close(fd);
}


void generate_files(int f_out, struct file_list *flist, char *local_name)
{
	int i;
	int phase = 0;
	char fbuf[MAXPATHLEN];
#ifdef HAVE_COPYFILE
	int *ea_map = NULL;
	int ea_saved = -1;
#endif

	if (verbose > 2) {
		rprintf(FINFO, "generator starting pid=%ld count=%d\n",
			(long)getpid(), flist->count);
	}

	if (verbose >= 2) {
		rprintf(FINFO,
			whole_file > 0
			? "delta-transmission disabled for local transfer or --whole-file\n"
			: "delta transmission enabled\n");
	}

	/* we expect to just sit around now, so don't exit on a
	   timeout. If we really get a timeout then the other process should
	   exit */
	io_timeout = 0;

#ifdef HAVE_COPYFILE
	/* APPLE: extended attribute files (._foo) need to be transferred
	 * after the corresponding file (foo).  This creates a map the size
	 * of flist with the number of the file that preempts the current 
	 * file's delivery.  Set to -1 if there's nothing to do.
	 */
	if (extended_attributes) {
	    int j;
	    struct file_struct *file2;
	    struct file_struct *file3;

	    if (verbose > 3)
		rprintf(FINFO,"initializing extended attribute map\n");
	    ea_map = malloc(sizeof(int)*flist->count);
	    if (!ea_map)
		    out_of_memory("extended attribute map");
	    for (i = 0; i < flist->count; ++i) {
		ea_map[i] = -1;
		file2 = flist->files[i];

		if (!file2->basename || strncmp(file2->basename, "._", 2))
		    continue;

		for (j = i; j < flist->count; ++j) {
		    file3 = flist->files[j];

		    if (!file3->basename)
			continue;

		    if(!(file2->dirname || file3->dirname)
			|| (file2->dirname && file3->dirname &&
			!strcmp(file3->dirname, file2->dirname))) {

			if(!strcmp(file3->basename, file2->basename + 2)) {
			    ea_map[i] = j;

			    if (verbose > 4)
				rprintf(FINFO,"mapped %s/%s (%d) -> %s/%s (%d)\n",
					(file2->dirname) ? file2->dirname : ".",
					file2->basename, i,
					(file2->dirname) ? file2->dirname : ".",
					file3->basename, j);
			    break;
			}
		    }
		}
	    }
	}
#endif

	for (i = 0; i < flist->count; i++) {
		struct file_struct *file = flist->files[i];
		struct file_struct copy;

#ifdef HAVE_COPYFILE
		if (extended_attributes) {
		    if(ea_map[i] < -1)
			continue;

		    if(ea_map[i] > 0) {
			/* save the current index and set it to the
			 * file to skip to
			 */
			if (verbose > 4)
			    rprintf(FINFO,"skipping from %d to %d\n", i, ea_map[i]);

			ea_saved = i;
			i = ea_map[i];
			ea_map[i] = -1;
		    }
next:		    file = flist->files[i];
		}
#endif

		if (!file->basename)
			continue;

		/* we need to ensure that any directories we create have writeable
		   permissions initially so that we can create the files within
		   them. This is then fixed after the files are transferred */
		if (!am_root && S_ISDIR(file->mode) && !(file->mode & S_IWUSR)) {
			copy = *file;
			/* XXX: Could this be causing a problem on SCO?  Perhaps their
			 * handling of permissions is strange? */
			copy.mode |= S_IWUSR; /* user write */
			file = &copy;
		}

		recv_generator(local_name ? local_name : f_name_to(file, fbuf),
			       file, i, f_out);


#ifdef HAVE_COPYFILE
		if (extended_attributes) {
		    if(ea_saved > -1) {
			ea_map[i] = -2;
			i = ea_saved;
			ea_saved = -1;
			goto next;
		    }
		}
#endif
	}

#ifdef HAVE_COPYFILE
	if (ea_map)
		free(ea_map);
#endif
	phase++;
	csum_length = SUM_LENGTH;
	ignore_times = 1;

	if (verbose > 2)
		rprintf(FINFO,"generate_files phase=%d\n",phase);

	write_int(f_out, -1);

	/* files can cycle through the system more than once
	 * to catch initial checksum errors */
	while ((i = get_redo_num()) != -1) {
		struct file_struct *file = flist->files[i];
		recv_generator(local_name ? local_name : f_name_to(file, fbuf),
			       file, i, f_out);
	}

	phase++;
	if (verbose > 2)
		rprintf(FINFO,"generate_files phase=%d\n",phase);

	write_int(f_out, -1);

	if (preserve_hard_links)
		do_hard_links();

	/* now we need to fix any directory permissions that were
	 * modified during the transfer */
	for (i = 0; i < flist->count; i++) {
		struct file_struct *file = flist->files[i];
		if (!file->basename || !S_ISDIR(file->mode))
			continue;
		recv_generator(local_name ? local_name : f_name(file),
			       file, i, -1);
	}

	if (verbose > 2)
		rprintf(FINFO,"generate_files finished\n");
}
