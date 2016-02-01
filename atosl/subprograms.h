/*
 *  Copyright (c) 2013, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#ifndef SUBPROGRAMS_
#define SUBPROGRAMS_

#include <stdint.h>

#include <dwarf.h>

#include "common.h"

#define SUBPROGRAMS_CACHE_MAGIC   0xcaceecac
#define SUBPROGRAMS_CACHE_VERSION 1
#define SUBPROGRAMS_CACHE_PATH    ".atosl-cache"

#ifndef DW_LANG_Swift
#define DW_LANG_Swift             0x1e
#endif

enum subprograms_type_t {
    SUBPROGRAMS_GLOBALS,
    SUBPROGRAMS_CUS
};

struct subprograms_options_t {
    int persistent:1;
    const char *cache_dir;
};

struct dwarf_subprogram_t *subprograms_load(Dwarf_Debug dbg,
                                            uint8_t uuid[UUID_LEN],
                                            enum subprograms_type_t type,
                                            struct subprograms_options_t *options);

#endif /* SUBPROGRAMS_ */

/* vim:set ts=4 sw=4 sts=4 expandtab: */
