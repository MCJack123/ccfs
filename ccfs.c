/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

#define FUSE_USE_VERSION 31
//#define _GNU_SOURCE 1

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse3/fuse.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "connection.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
    const char * url;
    int id;
    int show_help;
    int foreground;
} options;

#define OPTION(t, p) \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--id=", id),
    OPTION("-h", show_help),
    OPTION("--help", show_help),
    OPTION("-f", foreground),
    FUSE_OPT_END
};

static int handleError(const char * msg) {
    int retval = -EIO;
    if (strstr(msg, "File exists")) retval = -EEXIST;
    else if (strcmp(msg, "Out of space")) retval = -ENOSPC;
    else if (strstr(msg, "Access denied")) retval = -EACCES;
    else if (strstr(msg, "Permission denied")) retval = -EROFS;
    else if (strstr(msg, "Cannot write to directory")) retval = -EISDIR;
    else if (strstr(msg, "No such file")) retval = -ENOENT;
    else if (strstr(msg, "Not a directory")) retval = -ENOTDIR;
    else if (strstr(msg, "Invalid Path")) retval = -EINVAL;
    else if (strcmp(msg, "Connection closed")) retval = -EPIPE;
    else if (strcmp(msg, "Connection timed out") == 0) retval = -ETIMEDOUT;
    else if (strcmp(msg, "Too many directories to copy") == 0) retval = -ELOOP;
    else if (strcmp(msg, "Can't move a directory inside itself") == 0) retval = -EOPNOTSUPP;
    else if (strcmp(msg, "Cannot move a directory inside itself") == 0) retval = -EOPNOTSUPP;
    else if (strcmp(msg, "Too many files already open") == 0) retval = -EMFILE;
    free(msg);
    return retval;
}

static void *ccfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void)conn;
    cfg->intr = 1;
    cfg->kernel_cache = 0;
    cfg->no_rofd_flush = 1;
    return NULL;
}

static void ccfs_destroy(void *private_data) {
    disconnectFromServer();
}

static int ccfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    file_request_result_t res = sendFileRequest(CCPC_RAW_FILE_REQUEST_ATTRIBUTES, path, NULL);
    if (res.attributesRes.err == 1) return -ENOENT;
    else if (res.attributesRes.err == 2) return -EIO;
#ifdef __USE_XOPEN2K8
    stbuf->st_ctim.tv_sec = res.attributesRes.created / 1000;
    stbuf->st_ctim.tv_nsec = (res.attributesRes.created % 1000) * 1000000;
    stbuf->st_mtim.tv_sec = res.attributesRes.modified / 1000;
    stbuf->st_mtim.tv_nsec = (res.attributesRes.modified % 1000) * 1000000;
#else
    stbuf->st_ctime = res.attributesRes.created / 1000;
    stbuf->st_ctimensec = res.attributesRes.created * 1000000;
    stbuf->st_mtime = res.attributesRes.modified / 1000;
    stbuf->st_mtimensec = res.attributesRes.modified * 1000000;
#endif
    stbuf->st_atime = 0;
    stbuf->st_blksize = 1;
    stbuf->st_mode = (res.attributesRes.isReadOnly ? 0555 : 0777) | (res.attributesRes.isDir ? S_IFDIR : S_IFREG);
    stbuf->st_size = stbuf->st_blocks = res.attributesRes.size;
    stbuf->st_nlink = res.attributesRes.isDir ? 2 : 1;
    return 0;
}

static int ccfs_mkdir(const char * path, mode_t mode) {
    file_request_result_t res = sendFileRequest(CCPC_RAW_FILE_REQUEST_MAKEDIR, path, NULL);
    if (res.strRes != NULL) return handleError(res.strRes);
    return 0;
}

static int ccfs_delete(const char * path) {
    file_request_result_t res = sendFileRequest(CCPC_RAW_FILE_REQUEST_DELETE, path, NULL);
    if (res.strRes != NULL) return handleError(res.strRes);
    return 0;
}

static int ccfs_rename(const char * from, const char * to, unsigned int flags) {
#ifdef RENAME_EXCHANGE
    if (flags == RENAME_EXCHANGE) return -ENOSYS;
#endif
    file_request_result_t res = sendFileRequest(CCPC_RAW_FILE_REQUEST_MOVE, from, to);
    if (res.strRes != NULL) return handleError(res.strRes);
    return 0;
}

static int ccfs_statfs(const char * path, struct statvfs * stat) {
    stat->f_bsize = 1;
    file_request_result_t res = sendFileRequest(CCPC_RAW_FILE_REQUEST_GETFREESPACE, path, NULL);
    stat->f_bfree = stat->f_bavail = res.intRes;
    res = sendFileRequest(CCPC_RAW_FILE_REQUEST_GETCAPACITY, path, NULL);
    stat->f_blocks = res.intRes;
    stat->f_namemax = 255;
    stat->f_frsize = 0;
    return 0;
}

static int ccfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void)offset;
    (void)fi;
    (void)flags;

    file_request_result_t res = sendFileRequest(CCPC_RAW_FILE_REQUEST_LIST, path, NULL);
    if (res.listRes.size == 0xFFFFFFFF) return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);
    for (int i = 0; i < res.listRes.size; i++) {
        filler(buf, res.listRes.list[i], NULL, 0, 0);
        free(res.listRes.list[i]);
    }
    free(res.listRes.list);

    return 0;
}

struct cc_file_handle {
    uint32_t size;
    uint8_t flags;
    uint8_t * data;
};

static int ccfs_open(const char *path, struct fuse_file_info *fi) {
    if ((fi->flags & O_ACCMODE) == O_RDONLY) {
        struct cc_file_handle * handle = malloc(sizeof(struct cc_file_handle));
        handle->flags = (!O_BINARY || (fi->flags & O_BINARY) ? CCPC_RAW_FILE_REQUEST_OPEN_BINARY : 0);
        handle->size = readFile(path, !O_BINARY || (fi->flags & O_BINARY), &handle->data);
        if (handle->size == SIZE_MAX) {
            const char * msg = (const char*)handle->data;
            free(handle);
            return handleError(msg);
        }
        fi->fh = (uint64_t)handle;
        return 0;
    } else if ((fi->flags & O_ACCMODE) == O_WRONLY) {
        file_request_result_t res = sendFileRequest(CCPC_RAW_FILE_REQUEST_ISREADONLY, path, NULL);
        if (res.boolRes) return -EACCES;
        struct cc_file_handle * handle = malloc(sizeof(struct cc_file_handle));
        handle->size = 0;
        handle->flags = CCPC_RAW_FILE_REQUEST_OPEN_WRITE | ((fi->flags & O_APPEND) ? CCPC_RAW_FILE_REQUEST_OPEN_APPEND : 0) | (!O_BINARY || (fi->flags & O_BINARY) ? CCPC_RAW_FILE_REQUEST_OPEN_BINARY : 0);
        handle->data = NULL;
        fi->fh = (uint64_t)handle;
        return 0;
    } else return -EINVAL;
}

static int ccfs_create(const char * path, mode_t mode, struct fuse_file_info *fi) {
    (void)mode;
    const char * err = writeFile(path, 1, 0, "", 0);
    if (err != NULL) return handleError(err);
    struct cc_file_handle * handle = malloc(sizeof(struct cc_file_handle));
    handle->size = 0;
    handle->flags = CCPC_RAW_FILE_REQUEST_OPEN_WRITE | ((fi->flags & O_APPEND) ? CCPC_RAW_FILE_REQUEST_OPEN_APPEND : 0) | (!O_BINARY || (fi->flags & O_BINARY) ? CCPC_RAW_FILE_REQUEST_OPEN_BINARY : 0);
    handle->data = NULL;
    fi->fh = (uint64_t)handle;
    return 0;
}

static int ccfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)path;
    struct cc_file_handle * handle = (struct cc_file_handle *)fi->fh;
    if (handle->flags & CCPC_RAW_FILE_REQUEST_OPEN_WRITE) return 0;
    if (offset > handle->size) return 0;
    size_t count = offset + size > handle->size ? handle->size - offset : size;
    memcpy(buf, handle->data, count);
    return count;
}

static int ccfs_write(const char * path, const char * buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    (void)path;
    struct cc_file_handle * handle = (struct cc_file_handle *)fi->fh;
    if (!(handle->flags & CCPC_RAW_FILE_REQUEST_OPEN_WRITE)) return 0;
    if (handle->size < offset + size) {
        handle->data = realloc(handle->data, offset + size);
        handle->size = handle->size = offset + size;
    }
    memcpy(handle->data + offset, buf, size);
    return size;
}

static int ccfs_flush(const char * path, struct fuse_file_info *fi) {
    struct cc_file_handle * handle = (struct cc_file_handle *)fi->fh;
    const char * err = writeFile(path, handle->flags & CCPC_RAW_FILE_REQUEST_OPEN_BINARY, handle->flags & CCPC_RAW_FILE_REQUEST_OPEN_APPEND, handle->data, handle->size);
    if (err) return handleError(err);
    if (handle->flags & CCPC_RAW_FILE_REQUEST_OPEN_APPEND) {
        free(handle->data);
        handle->data = NULL;
        handle->size = 0;
    }
    return 0;
}

static int ccfs_release(const char * path, struct fuse_file_info *fi) {
    struct cc_file_handle * handle = (struct cc_file_handle *)fi->fh;
    if (handle) {
        if (handle->data != NULL) free(handle->data);
        free(handle);
    }
    return 0;
}

static const struct fuse_operations ccfs_oper = {
    .init = ccfs_init,
    .destroy = ccfs_destroy,
    .getattr = ccfs_getattr,
    .mkdir = ccfs_mkdir,
    .unlink = ccfs_delete,
    .rmdir = ccfs_delete,
    .rename = ccfs_rename,
    //.statfs = ccfs_statfs,
    .readdir = ccfs_readdir,
    .open = ccfs_open,
    .create = ccfs_create,
    .read = ccfs_read,
    .write = ccfs_write,
    .flush = ccfs_flush,
    .release = ccfs_release
};

static void show_help(const char *progname) {
    printf("usage: %s <url> <mountpoint> [options]\n\nfilesystem-specific options:\n\t--id=<number>\tWindow ID to access files on\n", progname);
}

int main(int argc, char *argv[]) {
    int ret;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    options.id = 0;
    options.foreground = 0;

    /* Parse options */
    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1) return 1;

    if (args.argc < 3) {
        show_help(argv[0]);
        fuse_opt_free_args(&args);
        return 1;
    }
    // grab URL and shift down
    options.url = args.argv[1];
    for (int i = 2; i < args.argc; i++) args.argv[i-1] = args.argv[i];
    args.argc--;

    /* When --help is specified, first print our own file-system
       specific help text, then signal fuse_main to show
       additional help (by adding `--help` to the options again)
       without usage: line (by setting argv[0] to the empty
       string) */
    if (options.show_help) {
        show_help(argv[0]);
        assert(fuse_opt_add_arg(&args, "--help") == 0);
        args.argv[0][0] = '\0';
    }

    /* Handle daemonization early, as we need to connect as the daemon */
    char* dir = malloc(4096);
    getcwd(dir, 4096);
    assert(fuse_daemonize(options.foreground) == 0);
    chdir(dir);
    free(dir);
    connectToServer(options.url, options.id);
    fuse_opt_add_arg(&args, "-f");

    ret = fuse_main(args.argc, args.argv, &ccfs_oper, NULL);
    fuse_opt_free_args(&args);
    return ret;
}