#pragma once
#include "dependencies.h"
#include "struct_url.hpp"

/*
 * The FUSE operations originally ripped from the hello_ll sample.
 */

static int httpfs_stat(fuse_ino_t ino, struct stat *stbuf)
{
    stbuf->st_ino = ino;
    switch (ino) {
        case 1:
            stbuf->st_mode = S_IFDIR | 0755;
            stbuf->st_nlink = 2;
            break;

        case 2: {
                    struct_url * url = thread_setup();
                    fprintf(stderr, "%s: %s: stat()\n", argv0, url->tname); /*DEBUG*/
                    stbuf->st_mode = S_IFREG | 0444;
                    stbuf->st_nlink = 1;
                    return (int) get_stat(url, stbuf);
                }
                break;

        default:
                errno = ENOENT;
                return -1;
    }
    return 0;
}

static void httpfs_getattr(fuse_req_t req, fuse_ino_t ino,
        struct fuse_file_info *fi)
{
    struct stat stbuf;

    (void) fi;

    memset(&stbuf, 0, sizeof(stbuf));
    if (httpfs_stat(ino, &stbuf) < 0)
        assert(errno),fuse_reply_err(req, errno);
    else
        fuse_reply_attr(req, &stbuf, 1.0);
}

static void httpfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    if (parent != 1 || strcmp(name, main_url.name) != 0){
        e.ino = 0;
    } else {
        e.ino = 2;
        if(httpfs_stat(e.ino, &e.attr) < 0){
            assert(errno);
            fuse_reply_err(req, errno);
            return;
        }

    }
    fuse_reply_entry(req, &e);
}

struct dirbuf {
    char *p;
    size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
        fuse_ino_t ino)
{
    struct stat stbuf;
    size_t oldsize = b->size;
    b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
    b->p = (char *) realloc(b->p, b->size);
    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = ino;
    fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
            (off_t) b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
        off_t off, size_t maxsize)
{
    assert(off >= 0);

    if (off < bufsize)
        return fuse_reply_buf(req, buf + off,
                min(bufsize - (size_t)off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

static void httpfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
        off_t off, struct fuse_file_info *fi)
{
    (void) fi;

    if (ino != 1)
        fuse_reply_err(req, ENOTDIR);
    else {
        struct dirbuf b;

        memset(&b, 0, sizeof(b));
        dirbuf_add(req, &b, ".", 1);
        dirbuf_add(req, &b, "..", 1);
        dirbuf_add(req, &b, main_url.name, 2);
        reply_buf_limited(req, b.p, b.size, off, size);
        free(b.p);
    }
}

static void httpfs_open(fuse_req_t req, fuse_ino_t ino,
        struct fuse_file_info *fi)
{
    if (ino != 2)
        fuse_reply_err(req, EISDIR);
    else if ((fi->flags & 3) != O_RDONLY)
        fuse_reply_err(req, EACCES);
    else{
        /* direct_io is supposed to allow partial reads. However, setting
         * the flag causes read length max at 4096 bytes which leads to
         * *many* requests, poor performance, and errors. Some resources
         * like TCP ports are recycled too fast for Linux to cope.
         */
        //fi->direct_io = 1;
        fuse_reply_open(req, fi);
    }
}

static void httpfs_read(fuse_req_t req, fuse_ino_t ino, size_t size,
        off_t off, struct fuse_file_info *fi)
{
    (void) fi;

    struct_url * url = thread_setup();
    ssize_t res;

    assert(ino == 2);

    assert(url->file_size >= off);

    size=min(size, (size_t)(url->file_size - off));

    if(url->file_size == off) {
        /* Handling of EOF is not well documented, returning EOF as error
         * does not work but this does.  */
        fuse_reply_buf(req, NULL,  0);
        return;
    }
    /* since we have to return all stuff requested the buffer cannot be
     * allocated in advance */
    if(url->req_buf
            && ( (url->req_buf_size < size )
                || ( (url->req_buf_size > size )
                    && (url->req_buf_size > MAX_REQUEST) ) ) ){
        free(url->req_buf);
        url->req_buf = 0;
    }
    if(! url->req_buf){
        url->req_buf_size = size;
        url->req_buf = new char[size];
    }

    if((res = get_data(url, off, size)) < 0){
        assert(errno);
        fuse_reply_err(req, errno);
    }else{
        fuse_reply_buf(req, url->req_buf, (size_t)res);
    }
}

struct MyFuse: public fuse_lowlevel_ops{
	MyFuse(){
		/**
		 * Look up a directory entry by name and get its attributes.
		 *
		 * Valid replies:
		 *   fuse_reply_entry
		 *   fuse_reply_err
		 *
		 * @param req request handle
		 * @param parent inode number of the parent directory
		 * @param name the name to look up
		 */
		this-> lookup = httpfs_lookup;
		/**
		 * Get file attributes
		 *
		 * Valid replies:
		 *   fuse_reply_attr
		 *   fuse_reply_err
		 *
		 * @param req request handle
		 * @param ino the inode number
		 * @param fi for future use, currently always NULL
		 */
		this->getattr =  httpfs_getattr;
		/**
		 * Read directory
		 *
		 * Send a buffer filled using fuse_add_direntry(), with size not
		 * exceeding the requested size.  Send an empty buffer on end of
		 * stream.
		 *
		 * fi->fh will contain the value set by the opendir method, or
		 * will be undefined if the opendir method didn't set any value.
		 *
		 * Valid replies:
		 *   fuse_reply_buf
		 *   fuse_reply_data
		 *   fuse_reply_err
		 *
		 * @param req request handle
		 * @param ino the inode number
		 * @param size maximum number of bytes to send
		 * @param off offset to continue reading the directory stream
		 * @param fi file information
		 */
		this->readdir =  httpfs_readdir;
		/**
		 * Open a file
		 *
		 * Open flags (with the exception of O_CREAT, O_EXCL, O_NOCTTY and
		 * O_TRUNC) are available in fi->flags.
		 *
		 * Filesystem may store an arbitrary file handle (pointer, index,
		 * etc) in fi->fh, and use this in other all other file operations
		 * (read, write, flush, release, fsync).
		 *
		 * Filesystem may also implement stateless file I/O and not store
		 * anything in fi->fh.
		 *
		 * There are also some flags (direct_io, keep_cache) which the
		 * filesystem may set in fi, to change the way the file is opened.
		 * See fuse_file_info structure in <fuse_common.h> for more details.
		 *
		 * Valid replies:
		 *   fuse_reply_open
		 *   fuse_reply_err
		 *
		 * @param req request handle
		 * @param ino the inode number
		 * @param fi file information
		 */
		this->open =  httpfs_open;
		/**
		 * Read data
		 *
		 * Read should send exactly the number of bytes requested except
		 * on EOF or error, otherwise the rest of the data will be
		 * substituted with zeroes.  An exception to this is when the file
		 * has been opened in 'direct_io' mode, in which case the return
		 * value of the read system call will reflect the return value of
		 * this operation.
		 *
		 * fi->fh will contain the value set by the open method, or will
		 * be undefined if the open method didn't set any value.
		 *
		 * Valid replies:
		 *   fuse_reply_buf
		 *   fuse_reply_iov
		 *   fuse_reply_data
		 *   fuse_reply_err
		 *
		 * @param req request handle
		 * @param ino the inode number
		 * @param size number of bytes to read
		 * @param off offset to read from
		 * @param fi file information
		 */
		this->read =  httpfs_read;
	}
};
static struct MyFuse httpfs_oper;
