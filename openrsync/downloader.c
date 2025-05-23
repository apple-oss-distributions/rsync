/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
 * Copyright (c) 2024, Klara, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include COMPAT_ENDIAN_H
#ifdef __APPLE__
#include <sys/time.h>
#endif

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>

#include "zlib/zlib.h"
#include "md4.h"

#include "extern.h"

#ifndef ACCESSPERMS
#define ACCESSPERMS	(S_IRWXU|S_IRWXG|S_IRWXO)
#endif

/*
 * A small optimisation: have a 1 MB pre-write buffer.
 * Disable the pre-write buffer by having this be zero.
 * (It doesn't affect performance much.)
 */
#define	OBUF_SIZE	(1024 * 1024)

enum	downloadst {
	DOWNLOAD_READ_NEXT = 0,
	DOWNLOAD_READ_LOCAL,
	DOWNLOAD_READ_REMOTE,
	DOWNLOAD_FLUSH_REMOTE,	/* I/O error -- flush until EOF */
};

static enum zlib_state	 dec_state; /* decompression state */
static z_stream		 dectx; /* decompression context */
static int decompress_reinit(void);
static int buf_copy(const char *, size_t, struct download *, struct sess *);

/*
 * Like struct upload, but used to keep track of what we're downloading.
 * This also is managed by the receiver process.
 */
struct	download {
	enum downloadst	    state; /* state of affairs */
	size_t		    idx; /* index of current file */
	int32_t		    fxiter; /* flist index translation iterator */
	struct blkset	    blk; /* its blocks */
	struct fmap	   *map; /* mmap of current file */
	int		    ofd; /* open origin file */
	int		    fd; /* open output file */
	char		   *fname; /* output filename */
	MD4_CTX		    ctx; /* current hashing context */
	off_t		    downloaded; /* total downloaded */
	off_t		    total; /* total in file */
	struct flist	   *fl; /* file list */
	size_t		    flsz; /* size of file list */
	int		    rootfd; /* destination directory */
	int		    tempfd; /* temp directory */
	int		    fdin; /* read descriptor from sender */
	char		   *obuf; /* pre-write buffer */
	size_t		    obufsz; /* current size of obuf */
	size_t		    obufmax; /* max size we'll wbuffer */
	size_t		    needredo; /* needs redo phase */
	size_t		    curtok; /* current token */
};


/*
 * Reinitialise a download context w/o overwriting the persistent parts
 * of the structure (like p->fl or p->flsz) for index "idx".
 * The MD4 context is pre-seeded.
 */
static void
download_reinit(struct sess *sess, struct download *p, size_t idx)
{
	int32_t seed = htole32(sess->seed);

	assert(p->state == DOWNLOAD_READ_NEXT);

	p->idx = idx;
	memset(&p->blk, 0, sizeof(struct blkset));
	p->map = NULL;
	p->ofd = -1;
	p->fd = -1;
	p->fname = NULL;
	MD4_Init(&p->ctx);
	p->downloaded = p->total = 0;
	/* Don't touch p->fl. */
	/* Don't touch p->flsz. */
	/* Don't touch p->rootfd. */
	/* Don't touch p->tempfd. */
	/* Don't touch p->fdin. */
	/* Don't touch p->obufsz. */
	/* Don't touch p->obufmax. */
	/* Don't touch p->needredo. */
	p->curtok = 0;
	MD4_Update(&p->ctx, &seed, sizeof(int32_t));
	decompress_reinit();
}

static inline bool
download_is_inplace(struct sess *sess, struct download *p, bool resumed_only)
{

	if (!sess_is_inplace(sess))
		return false;
	if (!resumed_only)
		return true;

	/*
	 * We're definitely inplace, but we're only a resumed transfer if we
	 * actually have the previous file mapped.
	 */
	return p->ofd >= 0;
}

/*
 * Handle the --partial-dir aspect of downloads, return the path to use for the
 * tmpdir.  Takes a buffer to store the result into, which should be at least
 * PATH_MAX in size.
 */
const char *
download_partial_path(struct sess *sess, const struct flist *f,
    char *path, size_t pathsz)
{
	const char *dirsep, *dir;
	int dirlen;

	assert(sess->opts->partial_dir != NULL);
	assert(f != NULL);

	if (sess->opts->partial_dir[0] == '/') {
		return sess->opts->partial_dir;
	}

	dir = f->path;
	dirsep = strrchr(dir, '/');
	if (dirsep == NULL) {
		dir = ".";
		dirlen = 1;
	} else {
		/*
		 * For all other subdirectories, we'll do a half-hearted
		 * attempt at normalizing it.
		 */
		while (dirsep > dir && *(dirsep - 1) == '/') {
			dirsep--;
		}

		/* Relative path of at least one level, not possible. */
		assert(dirsep != dir);

		dirlen = (int)(dirsep - dir);
	}

	assert(dirlen > 0);

	if ((size_t)snprintf(path, pathsz, "%.*s/%s", dirlen, dir,
	    sess->opts->partial_dir) > pathsz) {
		ERR("%s: partial-dir: path too long: %.*s/%s > %lu",
		    dir, dirlen, dir, sess->opts->partial_dir, pathsz);
		/* XXX: How do we error out here? */
	}
	return path;
}

const char *
download_partial_filepath(const struct flist *f)
{
	const char *path;

	path = strrchr(f->path, '/');
	if (path != NULL)
		path++;
	else
		path = f->path;
	return path;
}

static int
download_partial_fd(struct sess *sess, int rootfd, const struct flist *f)
{
	char partial_reldir[PATH_MAX];
	const char *partial_dir;
	struct stat st;
	int ret;

	partial_dir = download_partial_path(sess, f, partial_reldir,
	    sizeof(partial_reldir));

	ret = fstatat(rootfd, partial_dir, &st, AT_SYMLINK_NOFOLLOW);
	if (ret == -1 && errno != ENOENT)
		goto err;
	if (ret == 0 && !S_ISDIR(st.st_mode)) {
		/* Remove it if it's not a directory. */
		ret = unlinkat(rootfd, partial_dir, 0);
		if (ret == -1)
			goto err;

		/* Signal that we need to create it. */
		ret = -1;
	}

	if (ret == -1) {
		if (partial_dir != partial_reldir) {
			size_t len;

			/*
			 * mkpathat() modifies partial_dir[] so we must
			 * ensure it's in writable memory.
			 */
			len = strlcpy(partial_reldir, partial_dir, sizeof(partial_reldir));
			if (len >= sizeof(partial_reldir)) {
				errno = ENAMETOOLONG;
				goto err;
			}
		}

		ret = mkpathat(rootfd, partial_reldir,
		    S_IRUSR|S_IWUSR|S_IXUSR);

		/*
		 * Punt on EEXIST for now; we'll fail the below openat() if
		 * whatever happened was too weird.
		 */
		if (ret == -1 && errno != EEXIST)
			goto err;
	}

	/* Finally, we can open it. */
	return openat(rootfd, partial_dir, O_DIRECTORY);
err:
	return -1;
}

/*
 * Best-effort attempt to remove the partial dir.
 */
static void
download_cleanup_partial_dir(struct sess *sess, struct download *p,
    const struct flist *f)
{
	char partial_reldir[PATH_MAX];
	const char *partial_dir;
	struct stat st;
	int ret;

	partial_dir = download_partial_path(sess, f, partial_reldir,
	    sizeof(partial_reldir));
	ret = fstatat(p->rootfd, partial_dir, &st, AT_SYMLINK_NOFOLLOW);
	if (ret == -1)
		return;

	if (!S_ISDIR(st.st_mode))
		return;

	(void)unlinkat(p->rootfd, partial_dir, AT_REMOVEDIR);
}

/*
 * Cleanup any partial bits of a transfer.  This may mean anything from do
 * nothing to moving the file into place if we've been instructed to.  It may
 * be called from a signal context, so we should take care to only do
 * async-signal-safe things.
 *
 * This function may fail if we couldn't move the file into place for some
 * reason, but p->fd is guaranteed to be cleaned up either way.
 */
static int
download_cleanup_partial(struct sess *sess, struct download *p)
{
	struct flist *f;

	if (p->fl == NULL)
		return 1;

	f = &p->fl[p->idx];
	if (p->fd == -1) {
		if (f->pdfd >= 0)
			download_cleanup_partial_dir(sess, p, f);
		return 1;
	}

	/* Flush any buffered writes to the file */
	buf_copy(NULL, 0, p, sess);
	close(p->fd);
	p->fd = -1;

	if (p->fname == NULL)
		return 1;

	if (sess->opts->partial && sess->opts->inplace)
		return 1;

	if (sess->opts->partial) {
		char *fname;
		int pdfd;

		if (f->pdfd >= 0)
			return 1;

		if (sess->opts->partial_dir != NULL) {
			pdfd = download_partial_fd(sess, p->rootfd, f);
			if (pdfd == -1)
				return 0;

			fname = strrchr(f->path, '/');
			if (fname == NULL)
				fname = f->path;
			else
				fname++;
		} else {
			pdfd = p->rootfd;
			fname = f->path;
		}

		/*
		 * For partial transfers, we need to move the file into place if
		 * we're operating on a temp file.  If the rename fails, we do
		 * not try to remove it because partial files have been
		 * explicitly requested.  Better to just warn about the
		 * situation so that the user can manually recover the partial
		 * file and make a decision on it.
		 */
		if (platform_move_file(sess, f, p->rootfd, p->fname,
		    pdfd, fname, 0) == -1) {
			/*
			 * Don't leave the partial file laying around if
			 * --partial-dir was requested and we can't manage it.
			 */
			if (pdfd != p->rootfd) {
				(void)unlinkat(p->rootfd, p->fname, 0);
				close(pdfd);
			}
			return 0;
		}
		if (pdfd != p->rootfd)
			close(pdfd);
	} else if (sess->opts->temp_dir &&
	    !download_is_inplace(sess, p, false)) {
		char *fname;

		fname = strrchr(f->path, '/');
		if (fname == NULL)
			fname = f->path;
		else
			fname++;
		(void)unlinkat(p->tempfd, fname, 0);
	} else {
		(void)unlinkat(p->rootfd, p->fname, 0);
	}

	return 1;
}

/*
 * Free a download context.
 * If "cleanup" is non-zero, we also try to clean up the temporary file,
 * assuming that it has been opened in p->fd.
 */
static void
download_cleanup(struct sess *sess, struct download *p, int cleanup)
{

	if (p->map != NULL) {
		fmap_close(p->map);
		p->map = NULL;
	}
	if (p->ofd != -1) {
		close(p->ofd);
		p->ofd = -1;
	}
	if (cleanup) {
		if (!download_cleanup_partial(sess, p)) {
			ERR("%s: partial cleanup failed, left at %s",
			    p->fl[p->idx].path, p->fname);
		}
	} else if (p->fd != -1) {
		close(p->fd);
		p->fd = -1;
	}

	free(p->fname);
	p->fname = NULL;
	p->state = DOWNLOAD_READ_NEXT;
}

/*
 * Initial allocation of the download object using the file list "fl" of
 * size "flsz", the destination "rootfd", and the sender read "fdin".
 * Returns NULL on allocation failure.
 * On success, download_free() must be called with the pointer.
 */
struct download *
download_alloc(struct sess *sess, int fdin, struct flist *fl, size_t flsz,
	int rootfd, int tempfd)
{
	struct download	*p;

	if ((p = malloc(sizeof(struct download))) == NULL) {
		ERR("malloc");
		return NULL;
	}

	p->state = DOWNLOAD_READ_NEXT;
	p->fxiter = -1;
	p->fl = fl;
	p->flsz = flsz;
	p->rootfd = rootfd;
	p->tempfd = tempfd;
	p->fdin = fdin;
	p->needredo = 0;
	download_reinit(sess, p, 0);
	p->obufsz = 0;
	p->obuf = NULL;
	p->obufmax = OBUF_SIZE;
	if (p->obufmax && (p->obuf = malloc(p->obufmax)) == NULL) {
		ERR("malloc");
		free(p);
		return NULL;
	}
	return p;
}

size_t
download_needs_redo(struct download *p)
{

	return p->needredo;
}

/*
 * Perform all cleanups (including removing stray files) and free.
 * Passing a NULL to this function is ok.
 */
void
download_free(struct sess *sess, struct download *p)
{

	if (p == NULL)
		return;
	download_cleanup(sess, p, 1);
	free(p->obuf);
	free(p);
}

/*
 * Perform all cleanups (including removing stray files) without freeing,
 * because we're likely operating in a signal context.
 * Passing a NULL to this function is ok.
 */
void
download_interrupted(struct sess *sess, struct download *p)
{

	if (p == NULL)
		return;

	download_cleanup_partial(sess, p);
}

/*
 * Optimisation: instead of dumping directly into the output file, keep
 * a buffer and write as much as we can into the buffer.
 * That way, we can avoid calling write() too much, and instead call it
 * with big buffers.
 * To flush the buffer w/o changing it, pass 0 as "sz".
 * Returns zero on failure, non-zero on success.
 */
static int
buf_copy(const char *buf, size_t sz, struct download *p, struct sess *sess)
{
	size_t	 rem, tocopy;
	ssize_t	 ssz;

	assert(p->obufsz <= p->obufmax);

	/*
	 * Copy as much as we can.
	 * If we've copied everything, exit.
	 * If we have no pre-write buffer (obufmax of zero), this never
	 * gets called, so we never buffer anything.
	 */

	if (sz && p->obufsz < p->obufmax) {
		assert(p->obuf != NULL);
		rem = p->obufmax - p->obufsz;
		assert(rem > 0);
		tocopy = rem < sz ? rem : sz;
		memcpy(p->obuf + p->obufsz, buf, tocopy);
		sz -= tocopy;
		buf += tocopy;
		p->obufsz += tocopy;
		assert(p->obufsz <= p->obufmax);
		if (sz == 0)
			return 1;
	}

	/* Drain the main buffer. */

	if (p->obufsz) {
		assert(p->obufmax);
		assert(p->obufsz <= p->obufmax);
		assert(p->obuf != NULL);
		if (p->fd >= 0) {
			if (sess->opts->sparse && iszerobuf(p->obuf, p->obufsz)) {
				if (lseek(p->fd, p->obufsz, SEEK_CUR) == -1) {
					ERR("%s: lseek", p->fname);
					return 0;
				}
			} else {
				if ((ssz = write(p->fd, p->obuf, p->obufsz)) < 0) {
					ERR("%s: write", p->fname);
					return 0;
				} else if ((size_t)ssz != p->obufsz) {
					ERRX("%s: short write", p->fname);
					return 0;
				}
			}
		}
		p->obufsz = 0;
	}

	/*
	 * Now drain anything left.
	 * If we have no pre-write buffer, this is it.
	 */

	if (sz > 0 && p->fd >= 0) {
		if ((ssz = write(p->fd, buf, sz)) < 0) {
			ERR("%s: write", p->fname);
			return 0;
		} else if ((size_t)ssz != sz) {
			ERRX("%s: short write", p->fname);
			return 0;
		}
	}
	return 1;
}

/*
 * Infrastructure for --delay-updates.
 */
struct dlrename_entry {
	char *from;  /* Will be free()ed after use */
	const char *to;    /* Will not be free()ed after use */
	struct flist *file;
	char *rmdir; /* Directory to remove, will free() */
};
struct dlrename {
	struct dlrename_entry *entries;
	struct download *dl;
	const struct hardlinks *hl;
	int n;
	int fromfd;
	int tofd;
};

void
delayed_renames(struct sess *sess)
{
	int i;
	struct dlrename *dlr = sess->dlrename;
	struct dlrename_entry *curr;
	const struct flist *hl_p = NULL;
	struct download *p;
	int status;

	if (dlr == NULL)
		return;

	p = dlr->dl;
	for (i = 0; i < dlr->n; i++) {
		status = FLIST_SUCCESS;

		curr = &dlr->entries[i];
		LOG3("mv '%s' -> '%s'", curr->from, curr->to);
		if (sess->opts->hard_links)
			hl_p = find_hl(curr->file, dlr->hl);
		if (!platform_move_file(sess, curr->file,
		    dlr->fromfd, curr->from, dlr->tofd, curr->to, 1)) {
			status = FLIST_FAILED;
		}
		if (hl_p != NULL) {
			const char *path = curr->to;

			if (unlinkat(p->rootfd, path, 0) == -1) {
				if (errno != ENOENT) {
					status = FLIST_FAILED;
					ERRX1("unlink");
				}
			}

			if (linkat(p->rootfd, hl_p->path, p->rootfd, path,
			    0) == -1) {
				ERR("linkat");
				LOG0("Error while delayed hard linking '%s' "
				    "to '%s' ", hl_p->path, path);
			}

			hl_p = NULL;
		}
		if (curr->rmdir != NULL &&
		    unlinkat(dlr->tofd, curr->rmdir, AT_REMOVEDIR) == -1) {
			if (errno != ENOTEMPTY) {
				ERR("rmdir '%s'", curr->rmdir);
			}
		}

		curr->file->flstate |= status;
		free(curr->from);
		free(curr->rmdir);
		curr->from = NULL;
		curr->rmdir = NULL;
	}
	free(dlr->entries);
	dlr->entries = NULL;
	free(sess->dlrename);
	sess->dlrename = NULL;
}

/*
 * Fix metadata of the temp file based on the original destination file.  This
 * is the logical inverse of rsync_set_metadata*() as we're determining which
 * of the metadata won't be clobbered by preseration of the source file.
 */
static int
download_fix_metadata(const struct sess *sess, const char *fname, int fd,
    const struct stat *ost)
{
	uid_t uid = (uid_t)-1, puid = (uid_t)-1;
	gid_t gid = (gid_t)-1, pgid = (gid_t)-1;
	mode_t mode;

	if (!sess->opts->preserve_uids) {
		puid = geteuid();

		if (puid != ost->st_uid && puid == 0)
			uid = ost->st_uid;
	}

	if (!sess->opts->preserve_gids) {
		pgid = getegid();

		if (pgid != ost->st_gid)
			gid = ost->st_gid;
	}

	/*
	 * Unlike rsync_set_metadata, we're using perms from the local system
	 * and thus, we'll trust them a little bit more.
	 */
	mode = ost->st_mode & ALLPERMS;
	if (uid != (uid_t)-1 || gid != (gid_t)-1) {
		if (fchown(fd, uid, gid) == -1) {
			if (errno != EPERM) {
				ERR("%s: fchown", fname);
				return 0;
			}
			if (geteuid() == 0)
				WARNX("%s: identity unknown or not available "
				    "to user.group: %u.%u", fname, uid, gid);
		}
	}

	if (!sess->opts->preserve_perms && fchmod(fd, mode) == -1) {
		ERR("%s: fchmod", fname);
		return 0;
	}

	return 1;
}

/*
 * Deal with the conditional "follows" flags for extra metadata.
 */
static int
download_get_iflags(struct sess *sess, int fd, struct flist *f)
{
	int32_t iflags = f->iflags;

	if ((iflags & IFLAG_BASIS_FOLLOWS) != 0) {
		uint8_t basis;

		if (!io_read_byte(sess, fd, &basis)) {
			ERRX1("io_read_byte");
			return 0;
		}

		f->basis = basis;
	}
	if ((iflags & IFLAG_HLINK_FOLLOWS) != 0) {
		if (f->link != NULL) {
			free(f->link);
			f->link = NULL;
		}
		if (!io_read_vstring(sess, fd, &f->link)) {
			ERRX1("io_read_vstring");
			return 0;
		}
	}

	return 1;
}

enum protocol_token_result {
	TOKEN_ERROR,
	TOKEN_EOF,
	TOKEN_NEXT,
	TOKEN_RETRY,
};

static void
dec_state_change(enum zlib_state newstate)
{
	LOG4("decompress_state transition %d -> %d", dec_state, newstate);
	dec_state = newstate;
}

static enum protocol_token_result
protocol_token_cflush(struct sess *sess, struct download *p, char *dbuf)
{
	int		 res;
	size_t		 dsz;
	char		 tbuf[4];

	if (dectx.next_out == NULL) {
		return TOKEN_NEXT;
	}

	assert(dbuf != NULL);

	dectx.avail_in = 0;
	dectx.avail_out = MAX_CHUNK_BUF;
	res = inflate(&dectx, Z_SYNC_FLUSH);
	if (res != Z_OK && res != Z_BUF_ERROR) {
		ERRX("inflate protocol_token_cflush res=%d", res);
		if (dectx.msg) {
			ERRX("inflate error: %s", dectx.msg);
		}
		return TOKEN_ERROR;
	}
	dsz = MAX_CHUNK_BUF - dectx.avail_out;
	if (dsz != 0 && res != Z_BUF_ERROR) {
		if (!buf_copy(dbuf, dsz, p, sess)) {
			ERRX("buf_copy dbuf");
			return TOKEN_ERROR;
		}
		MD4_Update(&p->ctx, dbuf, dsz);
	}
	/*
	 * Check for compressor sync: 0x00 0x00 0xff 0xff
	 */
	if ((res = inflateSyncPoint(&dectx)) != 1) {
		ERRX("inflateSyncPoint res=%d", res);
		return TOKEN_ERROR;
	}
	dectx.avail_in = 4;
	dectx.next_in = (Bytef *)&tbuf;
	tbuf[0] = 0;
	tbuf[1] = 0;
	tbuf[2] = 0xff;
	tbuf[3] = 0xff;
	res = inflate(&dectx, Z_SYNC_FLUSH);
	/* res not checked on purpose, this is only to sync state */
	(void)res;

	return TOKEN_NEXT;
}

/* Returns 1 on success, 0 on error */
static int
decompress_reinit(void)
{
	int ret;

	if (dec_state == COMPRESS_INIT) {
		dectx.zalloc = NULL;
		dectx.zfree = NULL;
		dectx.next_in = NULL;
		dectx.avail_in = 0;
		dectx.next_out = NULL;
		dectx.avail_out = 0;
		if ((ret = inflateInit2(&dectx, -15)) != Z_OK) {
			ERRX("inflateInit2 res=%d", ret);
			return 0;
		}
		dec_state_change(COMPRESS_READY);
	} else if (dec_state >= COMPRESS_DONE) {
		dectx.next_in = NULL;
		dectx.avail_in = 0;
		dectx.next_out = NULL;
		dectx.avail_out = 0;
		inflateReset(&dectx);
		dec_state_change(COMPRESS_READY);
	}

	return 1;
}

static enum protocol_token_result
protocol_token_ff_compress(struct sess *sess, struct download *p, size_t tok)
{
	char		*buf = NULL, *dbuf = NULL;
	size_t		 sz, clen, rlen;
	off_t		 off;
	unsigned char	 hdr[5];
	int		 res;

	if (tok >= p->blk.blksz) {
		ERRX("%s: token not in block set: %zu (have %zu blocks)",
		    p->fname, tok, p->blk.blksz);
		return TOKEN_ERROR;
	}
	sz = (tok == p->blk.blksz - 1 && p->blk.rem) ? p->blk.rem : p->blk.len;
	assert(sz);
	assert(p->map != NULL);
	off = tok * p->blk.len;

	if (!fmap_trap(p->map)) {
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return TOKEN_NEXT;
	}
	buf = fmap_data(p->map, off, sz);

	if (!decompress_reinit()) {
		ERRX("decompress_reinit");
		fmap_untrap(p->map);
		return TOKEN_ERROR;
	}

	dbuf = sess->token_dbuf;
	if (sess->token_dbufsz < MAX_CHUNK_BUF) {
		dbuf = malloc(MAX_CHUNK_BUF);
		if (dbuf == NULL) {
			ERRX1("malloc");
			fmap_untrap(p->map);
			return TOKEN_ERROR;
		}

		free(sess->token_dbuf);
		sess->token_dbuf = dbuf;
		sess->token_dbufsz = MAX_CHUNK_BUF;
	}

	dectx.avail_in = 0;
	rlen = sz;
	clen = 0;
	hdr[0] = '\0';
	res = Z_OK;
	while (res == Z_OK) {
		if (dectx.avail_in == 0) {
			if (clen == 0) {
				/* Provide a stored-block header */
				clen = rlen;
				if (clen > 0xffff) {
					clen = 0xffff;
				}
				hdr[1] = clen;
				hdr[2] = clen >> 8;
				hdr[3] = ~hdr[1];
				hdr[4] = ~hdr[2];
				dectx.next_in = (Bytef *)hdr;
				dectx.avail_in = 5;
			} else {
				dectx.next_in = (Bytef *)buf;
				dectx.avail_in = (uInt)clen;
				rlen -= clen;
				clen = 0;
			}
		}
		dectx.next_out = (Bytef *)dbuf;
		dectx.avail_out = MAX_CHUNK_BUF;

		res = inflate(&dectx, Z_SYNC_FLUSH);

		if (res != Z_OK) {
			fmap_untrap(p->map);
			ERRX("inflate ff res=%d", res);
			if (dectx.msg) {
				ERRX("inflate error: %s", dectx.msg);
			}
			return TOKEN_ERROR;
		}
		if (dectx.avail_out == 0) {
			continue;
		} else if (rlen == 0) {
			break;
		}
	}

	fmap_untrap(p->map);
	return TOKEN_NEXT;
}

static enum protocol_token_result
protocol_token_ff(struct sess *sess, struct download *p, size_t tok)
{
	char		*buf = NULL;
	size_t		 sz;
	off_t		 off;
	int		 c;

	assert(p->state != DOWNLOAD_FLUSH_REMOTE);

	if (tok >= p->blk.blksz) {
		ERRX("%s: token not in block set: %zu (have %zu blocks)",
		    p->fname, tok, p->blk.blksz);
		return TOKEN_ERROR;
	}
	sz = (tok == p->blk.blksz - 1 && p->blk.rem) ? p->blk.rem : p->blk.len;
	assert(sz);
	assert(p->map != NULL);
	off = tok * p->blk.len;

	if (!fmap_trap(p->map)) {
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return TOKEN_NEXT;
	}
	buf = fmap_data(p->map, off, sz);

	/*
	 * Now we read from our block.
	 * We should only be at this point if we have a
	 * block to read from, i.e., if we were able to
	 * map our origin file and create a block
	 * profile from it.
	 */

	if (download_is_inplace(sess, p, true) && p->total == off) {
		fmap_untrap(p->map);

		/* Flush any pending data before we seek ahead. */
		if (!sess->opts->dry_run && !buf_copy(NULL, 0, p, sess)) {
			ERRX("buf_copy");
			return TOKEN_ERROR;
		}
		if (p->fd >= 0 && lseek(p->fd, sz, SEEK_CUR) == -1) {
			ERRX1("lseek");
			return TOKEN_ERROR;
		}
	} else {
		if (!buf_copy(buf, sz, p, sess)) {
			fmap_untrap(p->map);
			ERRX("buf_copy");
			return TOKEN_ERROR;
		}

		fmap_untrap(p->map);
	}

	if (!sess->opts->dry_run && !buf_copy(NULL, 0, p, sess)) {
		ERRX("buf_copy");
		return TOKEN_ERROR;
	}
	if (sess->opts->compress) {
		if (protocol_token_ff_compress(sess, p, tok) == TOKEN_ERROR) {
			ERRX1("protocol_token_ff_compress");
			return TOKEN_ERROR;
		}

		if (p->state == DOWNLOAD_FLUSH_REMOTE)
			return TOKEN_NEXT;
	}
	p->total += sz;
	sess->total_matched += sz;
	LOG4("%s: copied %zu B", p->fname, sz);

	if (!fmap_trap(p->map)) {
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return TOKEN_NEXT;
	}
	MD4_Update(&p->ctx, buf, sz);
	fmap_untrap(p->map);

	/* Fast-track more reads as they arrive. */
	if ((c = io_read_check(sess, p->fdin)) < 0) {
		ERRX1("io_read_check");
		return TOKEN_ERROR;
	} else if (c > 0) {
		return TOKEN_RETRY;
	}

	return TOKEN_RETRY;
}

static enum protocol_token_result
protocol_token_compressed(struct sess *sess, struct download *p)
{
	int32_t		 tok = (int32_t)p->curtok;
	uint8_t		 flag;
	size_t		 runsize, dsz;
	bool		 need_count;
	int		 res;
	char		*buf = NULL, *dbuf = NULL;

	if (!io_read_byte(sess, p->fdin, &flag)) {
		ERRX1("io_read_byte");
		return TOKEN_ERROR;
	}

	dbuf = sess->token_dbuf;
	if (sess->token_dbufsz < MAX_CHUNK_BUF) {
		dbuf = malloc(MAX_CHUNK_BUF);
		if (dbuf == NULL) {
			ERRX1("malloc");
			return TOKEN_ERROR;
		}

		free(sess->token_dbuf);
		sess->token_dbuf = dbuf;
		sess->token_dbufsz = MAX_CHUNK_BUF;
	}

	need_count = false;
	if ((flag & TOKEN_RUN_RELATIVE) == TOKEN_DEFLATED) {
		uint16_t bufsz;
		uint8_t sizelo;

		/* Read the lower 8 bits */
		if (!io_read_byte(sess, p->fdin, &sizelo)) {
			ERRX1("io_read_int");
			return TOKEN_ERROR;
		}
		bufsz = ((flag & ~TOKEN_DEFLATED) << 8) | sizelo;

		buf = sess->token_buf;
		if (sess->token_bufsz < bufsz) {
			buf = malloc(bufsz);
			if (buf == NULL) {
				ERRX1("malloc");
				return TOKEN_ERROR;
			}

			free(sess->token_buf);
			sess->token_buf = buf;
			sess->token_bufsz = bufsz;
		}

		if (!io_read_buf(sess, p->fdin, buf, bufsz)) {
			ERRX1("io_read_buf");
			return TOKEN_ERROR;
		}

		if (p->state == DOWNLOAD_FLUSH_REMOTE)
			return TOKEN_NEXT;

		dec_state_change(COMPRESS_RUN);
		dectx.next_in = (Bytef *)buf;
		dectx.avail_in = bufsz;
		dectx.next_out = (Bytef *)dbuf;
		dectx.avail_out = MAX_CHUNK_BUF;

		while (dectx.avail_in != 0 && (res = inflate(&dectx, Z_NO_FLUSH)) == Z_OK) {
			dsz = MAX_CHUNK_BUF - dectx.avail_out;
			if (!buf_copy(dbuf, dsz, p, sess)) {
				ERRX("buf_copy dbuf");
				return TOKEN_ERROR;
			}
			MD4_Update(&p->ctx, dbuf, dsz);
			p->total += dsz;
			p->downloaded += bufsz;
			sess->total_unmatched += dsz;
			dectx.next_out = (Bytef *)dbuf;
			dectx.avail_out = MAX_CHUNK_BUF;
		}
		if (res != Z_OK && res != Z_BUF_ERROR) {
			ERRX("inflate res=%d", res);
			if (dectx.msg) {
				ERRX("inflate error: %s", dectx.msg);
			}
			return TOKEN_ERROR;
		}
		/* We have exhausted the input stream, write out the remaining data */
		dsz = MAX_CHUNK_BUF - dectx.avail_out;
		if (dsz != 0) {
			if (!buf_copy(dbuf, dsz, p, sess)) {
				ERRX("buf_copy dbuf");
				return TOKEN_ERROR;
			}
			MD4_Update(&p->ctx, dbuf, dsz);
		}
		p->total += dsz;
		p->downloaded += bufsz;
		sess->total_unmatched += dsz;
		assert(dectx.avail_in == 0);

		dec_state_change(COMPRESS_DONE);

		return TOKEN_RETRY;
	} else if (dec_state == COMPRESS_DONE) {
		LOG4("decompress_state: flushing end of stream");
		if ((res = protocol_token_cflush(sess, p, dbuf)) != TOKEN_NEXT) {
			ERRX("protocol_token_cflush=%d", res);
			return TOKEN_ERROR;
		}
		dec_state_change(COMPRESS_READY);
	}

	if (flag == 0) {
		dec_state_change(COMPRESS_INIT);

		return TOKEN_EOF;
	} else if (flag & TOKEN_RELATIVE) {
		/*
		 * Matches both TOKEN_RELATIVE and TOKEN_RUN_RELATIVE.
		 * The token is the lower 6 bits of flag.
		 * Token is relative to where we previously wrote.
		 * If this is TOKEN_RUN_RELATIVE, it will be followed by a
		 * 16 bit run count, (we set need_count to read this below).
		 */
		tok += (flag & ~TOKEN_RUN_RELATIVE);
		flag >>= 6;
		need_count = (flag & 1);
	} else if ((flag & TOKEN_LONG) != 0) {
		if (!io_read_int(sess, p->fdin, &tok)) {
			ERRX1("io_read_int");
			return TOKEN_ERROR;
		}
		need_count = (flag & 1);
	}

	runsize = 0;
	if (need_count) {
		uint8_t part;

		if (!io_read_byte(sess, p->fdin, &part)) {
			ERRX1("io_read_byte");
			return TOKEN_ERROR;
		}

		runsize = part;

		if (!io_read_byte(sess, p->fdin, &part)) {
			ERRX1("io_read_byte");
			return TOKEN_ERROR;
		}

		runsize |= part << 8;

		dec_state_change(COMPRESS_SEQUENCE);
	}

	for (dsz = 0; dsz < runsize + 1 && p->state != DOWNLOAD_FLUSH_REMOTE;
	    dsz++) {
		if (dsz == runsize) {
			dec_state_change(COMPRESS_READY);
		}
		if ((res = protocol_token_ff(sess, p, tok++)) != TOKEN_RETRY) {
			if (p->state != DOWNLOAD_FLUSH_REMOTE)
				ERRX("protocol_token_ff res=%d", res);
			return res;
		}
	}

	p->curtok = tok - 1;

	return TOKEN_RETRY;
}

static enum protocol_token_result
protocol_token_raw(struct sess *sess, struct download *p)
{
	char		*buf = NULL;
	size_t		 sz, tok;
	int32_t		 rawtok;
	int		 c;

	if (!io_read_int(sess, p->fdin, &rawtok)) {
		ERRX1("io_read_int");
		return TOKEN_ERROR;
	}

	if (rawtok > 0) {
		sz = rawtok;
		buf = sess->token_buf;
		if (sess->token_bufsz < sz) {
			buf = malloc(sz);
			if (buf == NULL) {
				ERRX1("malloc");
				return TOKEN_ERROR;
			}

			free(sess->token_buf);
			sess->token_buf = buf;
			sess->token_bufsz = sz;
		}
		if (!io_read_buf(sess, p->fdin, buf, sz)) {
			ERRX1("io_read_buf");
			return TOKEN_ERROR;
		} else if (p->state != DOWNLOAD_FLUSH_REMOTE &&
		    !buf_copy(buf, sz, p, sess)) {
			ERRX("buf_copy");
			return TOKEN_ERROR;
		}
		p->total += sz;
		p->downloaded += sz;
		sess->total_unmatched += sz;
		LOG4("%s: received %zu B block", p->fname, sz);
		MD4_Update(&p->ctx, buf, sz);

		/* Fast-track more reads as they arrive. */

		if ((c = io_read_check(sess, p->fdin)) < 0) {
			ERRX1("io_read_check");
			return TOKEN_ERROR;
		} else if (c > 0) {
			return TOKEN_RETRY;
		}

		return TOKEN_NEXT;
	} else if (rawtok < 0) {
		tok = -rawtok - 1;
		if (p->state == DOWNLOAD_FLUSH_REMOTE)
			return TOKEN_NEXT;
		return protocol_token_ff(sess, p, tok);
	}

	return TOKEN_EOF;
}

/*
 * The downloader waits on a file the sender is going to give us, opens
 * and mmaps the existing file, opens a temporary file, dumps the file
 * (or metadata) into the temporary file, then renames.
 * This happens in several possible phases to avoid blocking.
 * Returns <0 on failure, 0 on no more data (end of phase), >0 on
 * success (more data to be read from the sender).
 */
int
rsync_downloader(struct download *p, struct sess *sess, int *ofd, size_t flsz,
    const struct hardlinks *hl)
{
	int32_t		 idx;
	struct  flist	*f = NULL;
	struct stat	 st, st2;
	unsigned char	 ourmd[MD4_DIGEST_LENGTH],
			 md[MD4_DIGEST_LENGTH];
	char             buf2[PATH_MAX];
	char            *usethis;
	enum protocol_token_result	tokres;
	int		 dirlen;
	struct dlrename  *renamer = NULL;

	if (sess->opts->dlupdates) {
		if (sess->dlrename == NULL) {
			sess->dlrename = malloc(sizeof(struct dlrename));
			if (sess->dlrename == NULL) {
				ERR("malloc renamer");
				goto out;
			}
			renamer = sess->dlrename;
			renamer->entries = NULL;
			renamer->hl = hl;
			renamer->dl = p;
			renamer->n = 0;
			renamer->fromfd = p->rootfd;
			renamer->tofd = p->rootfd;
		} else
			renamer = sess->dlrename;
	}

	/*
	 * If we don't have a download already in session, then the next
	 * one is coming in.
	 * Read either the stop (phase) signal from the sender or block
	 * metadata, in which case we open our file and wait for data.
	 */

	if (p->state == DOWNLOAD_READ_NEXT) {
		const char *path;
		int32_t sendidx;
		int32_t iflags;
		int rootfd;

		if (!io_read_int(sess, p->fdin, &sendidx)) {
			ERRX1("io_read_int");
			return -1;
		} else if (sendidx < 0) {
			LOG3("downloader: phase complete");
			p->fxiter = -1;
			return 0;
		}

		if (!protocol_itemize) {
			iflags = IFLAG_TRANSFER | IFLAG_MISSING_DATA;
		} else {
			if (!io_read_short(sess, p->fdin, &iflags)) {
				ERRX1("io_read_short");
				return -1;
			}
		}

		/* Check for keep-alive packet */
		if (iflags == IFLAG_NEW) {
			if ((uint32_t)sendidx == sess->sender_flsz) {
				/* Keep alive packet, do nothing */
				return 1;
			}

			ERRX1("invalid sendidx %d for keep alive packet",
			    sendidx);
			return -1;
		} else if ((uint32_t)sendidx == sess->sender_flsz) {
			ERRX1("invalid item flags 0x%x for sendidx %d",
			    iflags, sendidx);
			return -1;
		}

		/*
		 * Translate the sender's index to our local flist
		 * index since we may have, e.g., trimmed duplicates.
		 */
		idx = -1;
		for (size_t i = 0; i < p->flsz; i++) {
			p->fxiter = (p->fxiter + 1) % p->flsz;

			if (p->fl[p->fxiter].sendidx == sendidx) {
				idx = p->fxiter;
				break;
			}
		}
		if (idx == -1) {
			ERRX1("sendidx %d translation failed", sendidx);
			return -1;
		}

		f = &p->fl[idx];
		f->iflags = iflags;

		if (!download_get_iflags(sess, p->fdin, f)) {
			ERRX1("download_get_iflags");
			return -1;
		}

		sess->total_read_lf = sess->total_read;
		sess->total_write_lf = sess->total_write;

		if ((f->iflags & IFLAG_TRANSFER) == 0) {
			bool hlink = (f->iflags & IFLAG_HLINK_FOLLOWS) != 0;
			bool sig = (f->iflags & SIGNIFICANT_IFLAGS) != 0;

			if (sig || hlink || sess->itemize || verbose > 1) {
				bool local = (f->iflags & IFLAG_LOCAL_CHANGE) != 0;
				bool dir = S_ISDIR(f->st.mode);

				if (local || dir || hlink || sess->itemize)
					log_item(sess, f);
				else if (verbose > 1)
					log_item_impl(sess, f);
			}

			return 1;
		}

		if (!sess->lateprint || sess->opts->dry_run)
			log_item(sess, f);

		/*
		 * Short-circuit: dry_run mode does nothing, with one exception:
		 * if we're the client on an --only-write-batch transfer, we
		 * need to receive the data, record it and throw it away.
		 */
		if (sess->opts->dry_run && sess->wbatch_fd == -1)
			return 1;

		/*
		 * Now get our block information.
		 * This is all we'll need to reconstruct the file from
		 * the map, as block sizes are regular.
		 */

		download_reinit(sess, p, idx);
		if (!blk_send_ack(sess, p->fdin, &p->blk)) {
			ERRX1("blk_send_ack");
			goto out;
		}

		/*
		 * Next, we want to open the existing file for using as
		 * block input.
		 * We do this in a non-blocking way, so if the open
		 * succeeds, then we'll go reentrant til the file is
		 * readable and we can mmap() it.
		 * Set the file descriptor that we want to wait for.
		 */

		p->state = DOWNLOAD_READ_LOCAL;

		rootfd = p->rootfd;
		path = f->path;
		if (f->pdfd >= 0) {
			rootfd = f->pdfd;
			path = download_partial_filepath(f);
		}
		if (f->basis == BASIS_FUZZY && f->link) {
			/* We have a fuzzy match, open it instead */
			p->ofd = openat(rootfd, f->link, O_RDONLY | O_NONBLOCK);
		} else {
			p->ofd = openat(rootfd, path, O_RDONLY | O_NONBLOCK);
		}

		if (p->ofd == -1 && errno != ENOENT && rootfd != -1) {
			ERR("%s: rsync_downloader: openat", path);
			goto out;
		} else if (p->ofd != -1) {
			*ofd = p->ofd;
			if (sess->opts->no_cache) {
#if defined(F_NOCACHE)
				fcntl(p->ofd, F_NOCACHE);
#elif defined(O_DIRECT)
				int getfl;

				if ((getfl = fcntl(p->ofd, F_GETFL)) < 0) {
					warn("fcntl failed");
				} else {
					fcntl(p->ofd, F_SETFL, getfl | O_DIRECT);
				}
#endif
			}
			return 1;
		}

		/* Fall-through: there's no file. */
	}

	/*
	 * At this point, the server is sending us data and we want to
	 * hoover it up as quickly as possible or we'll deadlock.
	 * We want to be pulling off of f->fdin as quickly as possible,
	 * so perform as much buffering as we can.
	 */

	f = &p->fl[p->idx];

	/*
	 * Next in sequence: we have an open download session but
	 * haven't created our temporary file.
	 * This means that we've already opened (or tried to open) the
	 * original file in a nonblocking way, and we can map it.
	 */

	if (p->state == DOWNLOAD_READ_LOCAL) {
		assert(p->fname == NULL);

		if (sess->opts->dry_run && sess->wbatch_fd == -1) {
			/*
			 * Ideally we'd just be able to drive the token protocol
			 * a little more cleanly.
			 */
			*ofd = -1;
			p->state = DOWNLOAD_READ_REMOTE;
			return 1;
		}

		/*
		 * Try to fstat() the file descriptor if valid and make
		 * sure that we're still a regular file.
		 * Then, if it has non-zero size, mmap() it for hashing.
		 */

		if (p->ofd != -1 &&
		    fstat(p->ofd, &st) == -1) {
			ERR("%s: fstat", f->path);
			goto out;
		} else if (p->ofd != -1 && !S_ISREG(st.st_mode)) {
			WARNX("%s: not regular", f->path);
			goto out;
		}

		if (p->ofd != -1 && st.st_size > 0) {
			p->map = fmap_open(f->path, p->ofd, st.st_size);
			if (p->map == NULL)
				goto out;
#ifdef __APPLE__
			/* Temporary diagnostics */
			if (syslog_trace) {
				size_t nblks;

				nblks = p->blk.blksz;
				if (p->blk.rem != 0)
					nblks--;
				os_log_info(syslog_trace_obj,
				    "updating file[%llu]: %zu blocks of %zu bytes + %zu residual",
				    st.st_size, nblks, p->blk.len, p->blk.rem);
			}
#endif
		}

		/* Success either way: we don't need this. */

		*ofd = -1;

		/*
		 * For the only-write-batch case, we need to map
		 * the file to do the delta algorithm on it.
		 */
		if (sess->opts->dry_run && sess->wbatch_fd != -1) {
			p->state = DOWNLOAD_READ_REMOTE;
			return 1;
		}

		/* Create the temporary file. */
		if (download_is_inplace(sess, p, false) || f->pdfd >= 0) {
			char *basename;
			const char *path = f->path;
			int rootfd = p->rootfd;

			if (f->pdfd >= 0) {
				rootfd = f->pdfd;
				path = download_partial_filepath(f);
			}
			p->fd = openat(rootfd, path, O_RDWR | O_CREAT | O_NONBLOCK,
			    f->st.mode & ACCESSPERMS);
			if (p->fd == -1) {
				ERRX1("%s: open", path);
				goto out;
			}

			basename = strrchr(f->path, '/');
			if (basename == NULL)
				basename = f->path;
			else
				basename++;
			p->fname = strdup(basename);
			if (p->fname == NULL) {
				ERRX1("strdup");
				goto out;
			}

			LOG3("%s: writing inplace", f->path);

			if (sess->role->append && fmap_size(p->map) > 0) {
				if (!fmap_trap(p->map)) {
					p->state = DOWNLOAD_FLUSH_REMOTE;
				} else {
					hash_fmap_chunks(p->map,
					    fmap_size(p->map),  &p->ctx);
					fmap_untrap(p->map);

					if (lseek(p->fd, 0, SEEK_END) !=
					    st.st_size) {
						ERRX1("lseek");
						goto out;
					}
				}
			}
		} else {
			if (mktemplate(&p->fname, f->path,
			    sess->opts->recursive || strchr(f->path, '/') != NULL,
			    IS_TMPDIR) == -1) {
				ERRX1("mktemplate");
				goto out;
			}

			if ((p->fd = mkstempat(TMPDIR_FD, p->fname)) == -1) {
				ERR("mkstempat: '%s'", p->fname);
				sess->total_errors++;
			} else if (p->ofd != -1 &&
			    !download_fix_metadata(sess, p->fname, p->fd,
			    &st)) {
				goto out;
			}

			/*
			 * FIXME: we can technically wait until the temporary
			 * file is writable, but since it's guaranteed to be
			 * empty, I don't think this is a terribly expensive
			 * operation as it doesn't involve reading the file into
			 * memory beforehand.
			 */

			LOG3("%s: temporary: %s", f->path, p->fname);
		}

		if (sess->opts->no_cache) {
#if defined(F_NOCACHE)
			if (p->ofd >= 0)
				fcntl(p->ofd, F_NOCACHE);
			if (p->fd >= 0)
				fcntl(p->fd, F_NOCACHE);
#elif defined(O_DIRECT)
			int getfl;

			if (p->ofd >= 0) {
				if ((getfl = fcntl(p->ofd, F_GETFL)) < 0) {
					warn("fcntl failed");
				} else {
					fcntl(p->ofd, F_SETFL, getfl | O_DIRECT);
				}
			}
			if (p->fd >= 0) {
				if ((getfl = fcntl(p->fd, F_GETFL)) < 0) {
					warn("fcntl failed");
				} else {
					fcntl(p->fd, F_SETFL, getfl | O_DIRECT);
				}
			}
#endif
		}

		p->state = DOWNLOAD_READ_REMOTE;
		return 1;
	}

	/*
	 * This matches the sequence in blk_flush().
	 * If we've gotten here, then we have a possibly-open map file
	 * (not for new files) and our temporary file is writable.
	 * We read the size/token, then optionally the data.
	 * The size >0 for reading data, 0 for no more data, and <0 for
	 * a token indicator.
	 */

	if (sess->opts->no_cache) {
#if defined(F_NOCACHE)
		if (p->ofd >= 0)
			fcntl(p->ofd, F_NOCACHE);
		if (p->fd >= 0)
			fcntl(p->fd, F_NOCACHE);
#elif defined(O_DIRECT)
		int getfl;

		if (p->ofd >= 0) {
			if ((getfl = fcntl(p->ofd, F_GETFL)) < 0) {
				warn("fcntl failed");
			} else {
				fcntl(p->ofd, F_SETFL, getfl | O_DIRECT);
			}
		}
		if (p->fd >= 0) {
			if ((getfl = fcntl(p->fd, F_GETFL)) < 0) {
				warn("fcntl failed");
			} else {
				fcntl(p->fd, F_SETFL, getfl | O_DIRECT);
			}
		}
#endif
	}
again:
	rsync_progress(sess, p->fl[p->idx].st.size, p->total, false,
	    p->idx, p->flsz);

	assert(p->state == DOWNLOAD_READ_REMOTE ||
	    p->state == DOWNLOAD_FLUSH_REMOTE);
	assert(p->fname != NULL || sess->opts->dry_run);
	assert(p->fdin != -1);

	if (sess->opts->compress)
		tokres = protocol_token_compressed(sess, p);
	else
		tokres = protocol_token_raw(sess, p);
	switch (tokres) {
	case TOKEN_EOF:
		break;
	case TOKEN_RETRY:
		goto again;
	case TOKEN_NEXT:
		return 1;
	case TOKEN_ERROR:
	default:
		goto out;
	}

	if (!sess->opts->dry_run && p->state == DOWNLOAD_READ_REMOTE &&
	    !buf_copy(NULL, 0, p, sess)) {
		ERRX("buf_copy");
		goto out;
	}

	/*
	 * Just clear anything that was left in the output buffer; we weren't
	 * going to waste disk writes on a failed file.
	 */
	if (p->state == DOWNLOAD_FLUSH_REMOTE) {
		WARNX("%s: file truncated while reading",
		    p->fl[p->idx].path);
		p->obufsz = 0;
	}

	assert(p->fd < 0 || p->obufsz == 0 || sess->opts->dry_run);
	assert(tokres == TOKEN_EOF);

	/*
	 * Make sure our resulting MD4 hashes match.
	 * FIXME: if the MD4 hashes don't match, then our file has
	 * changed out from under us.
	 * This should require us to re-run the sequence in another
	 * phase.
	 */

	MD4_Final(ourmd, &p->ctx);

	if (!io_read_buf(sess, p->fdin, md, MD4_DIGEST_LENGTH)) {
		ERRX1("io_read_buf");
		goto out;
	} else if (memcmp(md, ourmd, MD4_DIGEST_LENGTH)) {
		/*
		 * If this is our second shot at a file and it still doesn't
		 * match, we'll just give up.
		 */
		WARNX("%s: hash does not match, %s redo", p->fname,
		    (f->flstate & FLIST_REDO) != 0 ? "will not" : "will");
		if ((f->flstate & FLIST_REDO) != 0) {
			f->flstate |= FLIST_FAILED;
			goto out;
		}

		f->flstate |= FLIST_REDO;
		p->needredo++;
		goto done;
	}

	/*
	 * Once we successfully transfer it, unmark it for redo so that we don't
	 * erroneously clean it up later.
	 */
	f->flstate = (f->flstate & ~FLIST_REDO) | FLIST_COMPLETE;
	sess->total_files_xfer++;
	sess->total_xfer_size += f->st.size;

	/* We can still get here with a DRY_XFER in some cases. */
	if (p->fd < 0 || sess->opts->dry_run)
		goto done;

	if (sess->opts->backup) {
		if (fstatat(p->rootfd, f->path, &st2, 0) == -1) {
			/*
			 * As-of-now missing file is OK, however
			 * we take no action for --backup.
			 */
			if (errno != ENOENT) {
				ERR("%s: stat during --backup", f->path);
				goto out;
			}
		} else if (sess->opts->backup_dir != NULL) {
			LOG3("%s: doing backup-dir to %s", f->path,
			    sess->opts->backup_dir);
			usethis = f->path;
			while (strncmp(usethis, "./", 2) == 0) {
				usethis += 2;
			}
			if (snprintf(buf2, sizeof(buf2), "%s/%s%s",
			    sess->opts->backup_dir, usethis,
			    sess->opts->backup_suffix) >= (int)sizeof(buf2)) {
				ERR("%s: backup-dir: compound backup path "
				    "too long: %s/%s%s >= %d", f->path,
				    sess->opts->backup_dir, usethis,
				    sess->opts->backup_suffix,
				    (int)sizeof(buf2));
				goto out;
			}
			if (backup_to_dir(sess, p->rootfd, f, buf2,
			    st2.st_mode) == -1) {
				ERR("%s: backup_to_dir: %s", f->path, buf2);
				goto out;
			}
		} else if (!S_ISDIR(st2.st_mode)) {
			LOG3("%s: doing backup", f->path);
			if (snprintf(buf2, sizeof(buf2), "%s%s", f->path,
			    sess->opts->backup_suffix) >= (int)sizeof(buf2)) {
				ERR("%s: backup: compound backup path too "
				    "long: %s%s >= %d", f->path, f->path,
				    sess->opts->backup_suffix,
				    (int)sizeof(buf2));
				goto out;
			}
			if (backup_file(p->rootfd, f->path,
			    p->rootfd, buf2, 1, &f->dstat) == -1) {
				ERR("%s: backup_file: %s", f->path, buf2);
				sess->total_errors++;
			}

		}
	}

	/* Adjust our file metadata (uid, mode, etc.). */

	if (!rsync_set_metadata(sess, p->ofd == -1, p->fd, f, p->fname)) {
		ERRX1("rsync_set_metadata");
		goto out;
	}
	/* 
	 * Finally, rename the temporary to the real file, unless
	 * --delay-updates is in effect, in which case it is going to
	 * the .~tmp~ subdirectory for now and is renamed later in
	 * a batch with all the other new or changed files.
	 */
	if (sess->opts->dlupdates) {
		struct dlrename_entry *prev, *curr;

		prev = NULL;
		if (renamer->entries == NULL) {
			renamer->entries = calloc(flsz,
				sizeof(struct dlrename_entry));
			if (renamer->entries == NULL) {
				ERR("malloc dlrenamer entries");
				goto out;
			}
			renamer->n = 0;
		}
		if (renamer->n > 0)
			prev = &renamer->entries[renamer->n - 1];
		renamer->n++;
		curr = &renamer->entries[renamer->n - 1];

		usethis = strrchr(f->path, '/');
		if (usethis == NULL)
			usethis = f->path;
		else
			usethis++;

		/*
		 * dirlen is either 0 and we're at the root, or dirlen is
		 * non-zero and it includes the trailing slash.
		 */
		dirlen = (int)(usethis - f->path);
		assert(usethis == f->path || *(usethis - 1) == '/');
		if (snprintf(buf2, sizeof(buf2), "%.*s.~tmp~",
		    dirlen, f->path) > (int)sizeof(buf2)) {
			ERR("%s: delayed-update: compound path too "
			    "long: %.*s.~tmp~ > %d", f->path,
			    dirlen, f->path, (int)sizeof(buf2));
			goto out;
		}

		if (prev != NULL && strcmp(buf2, prev->rmdir) == 0) {
			/*
			 * No need to try rmdir(2) every single time; if we have
			 * another entry going to the same directory, then move
			 * rmdir just a little later.
			 */
			curr->rmdir = prev->rmdir;
			prev->rmdir = NULL;
		} else {
			curr->rmdir = strdup(buf2);
			if (curr->rmdir == NULL) {
				ERR("strdup");
				goto out;
			}

			if (mkpathat(p->rootfd, curr->rmdir, 0700) == -1 &&
			    errno != EEXIST) {
				ERR("mkpathat '%s'", curr->rmdir);
				free(curr->rmdir);
				curr->rmdir = NULL;
				goto out;
			}
		}

		if (snprintf(buf2, sizeof(buf2), "%s/%s", curr->rmdir,
		    f->path + dirlen) > (int)sizeof(buf2)) {
			ERR("%s: delayed-update: compound path too "
			    "long: .~tmp~/%s > %d", f->path,
			    f->path, (int)sizeof(buf2));
			goto out;
		}
		usethis = buf2;
	} else {
		usethis = f->path;
	}
	if (!download_is_inplace(sess, p, false)) {
		int fromfd;

		fromfd = TMPDIR_FD;
		if (f->pdfd >= 0)
			fromfd = f->pdfd;
		if (!platform_move_file(sess, f, fromfd, p->fname,
		    p->rootfd, usethis, usethis == f->path))
			goto out;
	}

	/*
	 * Let the platform finalize the transfer.
	 */
	if (!platform_finish_transfer(sess, f, p->rootfd, usethis))
		goto out;

	if (sess->opts->dlupdates) {
		struct dlrename_entry *entry = &renamer->entries[renamer->n - 1];

		entry->from = strdup(usethis);
		if (entry->from == NULL) {
			ERR("strdup");
			goto out;
		}

		entry->file = f;
		entry->to = f->path;
		/* Status update is deferred until the update is done. */
	} else {
		f->flstate |= FLIST_SUCCESS;
		/*
		 * This file has been transferred, so unmark it to be
		 * hardlinked, and it will be come the "leader" of this
		 * group of hardlinks, and the other files will be linked
		 * to this first transferred file in the group.
		 */
		f->flstate &= ~FLIST_NEED_HLINK;
	}

	rsync_progress(sess, p->fl[p->idx].st.size, p->fl[p->idx].st.size,
	    true, p->idx, p->flsz);

	if (sess->lateprint)
		log_item(sess, f);

done:
	/*
	 * If we're redoing it, then we need to go ahead and clean up the file
	 * or move it into a --partial-dir.
	 */
	download_cleanup(sess, p, (f->flstate & FLIST_REDO) != 0);
	return 1;
out:
	if (f != NULL)
		f->flstate |= FLIST_FAILED;
	download_cleanup(sess, p, 1);
	return -1;
}
