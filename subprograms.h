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

enum subprograms_type_t {
    SUBPROGRAMS_GLOBALS,
    SUBPROGRAMS_CUS
};

struct dwarf_subprogram_t *subprograms_load(Dwarf_Debug dbg,
                                            enum subprograms_type_t type);

#endif /* SUBPROGRAMS_ */

/* vim:set ts=4 sw=4 sts=4 expandtab: */
