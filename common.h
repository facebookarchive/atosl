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

#define DWARF_ASSERT(ret, err) \
    do { \
        if (ret == DW_DLV_ERROR) { \
            fatal("dwarf_errmsg: %s", dwarf_errmsg(err)); \
        } \
    } while (0);

#endif /* COMMON_ */
