/*
 *  Copyright (c) 2013, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef COMMON_
#define COMMON_

#include <libdwarf.h>

#define USAGE "Usage: atosl -o|--dsym <FILENAME> [OPTIONS]... <ADDRESS>..."

#define UUID_LEN 16

#ifndef MAX
#define MAX(x,y) ((x)>(y)?(x):(y))
#endif

struct dwarf_subprogram_t;
struct dwarf_subprogram_t {
    const char *name;
    Dwarf_Addr lowpc;
    Dwarf_Addr highpc;
    struct dwarf_subprogram_t *next;
};

#define fatal(args...) common_fatal(__FILE__, __LINE__, args)
void common_fatal(const char *file, int lineno, const char *format, ...);

#define fatal_usage(args...) common_fatal_usage(__FILE__, __LINE__, args)
void common_fatal_usage(const char *file, int lineno, const char *format, ...);

#define fatal_file(args...) common_fatal_file(__FILE__, __LINE__, args)
void common_fatal_file(const char *file, int lineno, int ret);

#define warning(args...) common_warning(__FILE__, __LINE__, args)
void common_warning(const char *file, int lineno, const char *format, ...);

#define DWARF_ASSERT(ret, err) \
    do { \
        if (ret == DW_DLV_ERROR) { \
            fatal("dwarf_errmsg: %s", dwarf_errmsg(err)); \
        } \
    } while (0);

/* Wrapper to call write() in a loop until all data is written */
static inline ssize_t
_write(int fd, const void *buf, size_t count)
{
    ssize_t written = 0;
    ssize_t ret = 0;
    while (written < count) {
        ret = write(fd, buf+written, count-written);
        if (ret == 0)
            return written;
        else if (ret < 0)
            return ret;
        written += ret;
    }
    return written;
}

/* Wrapper to call read() in a loop until all data is read */
static inline ssize_t _read(int fd, void *buf, size_t count)
{
    ssize_t n_read = 0;
    ssize_t ret = 0;
    while (n_read < count) {
        ret = read(fd, buf+n_read, count-n_read);
        if (ret == 0)
            return n_read;
        else if (ret < 0)
            return ret;
        n_read += ret;
    }
    return n_read;
}

#endif /* COMMON_ */
