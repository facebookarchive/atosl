/*
 *  Copyright (c) 2013, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <dwarf.h>
#include <libdwarf.h>

#include "subprograms.h"
#include "common.h"

/* This method walks the compilation units to find the symbols. It's faster
 * than caching the globals, but it requires a little more manual work and
 * seems to be missing C++ symbols at the moment.  Note also that it's likely
 * only faster because of how slow dwarf_offdie is. It's probably best to
 * switch to cache_globals if we fix that */

/* List a function if it's in the given DIE.
*/
static struct dwarf_subprogram_t *read_cu_entry(
        struct dwarf_subprogram_t *subprograms,
        Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die the_die)
{
    char* die_name = 0;
    Dwarf_Error err;
    Dwarf_Half tag;
    Dwarf_Addr lowpc = 0;
    Dwarf_Addr highpc = 0;
    char *filename;
    struct dwarf_subprogram_t *subprogram = NULL;
    int rc;
    Dwarf_Attribute attrib = 0;

    rc = dwarf_tag(the_die, &tag, &err);
    if (rc != DW_DLV_OK)
        fatal("unable to parse dwarf tag");

    /* Only interested in subprogram DIEs here */
    if (tag != DW_TAG_subprogram)
        return subprograms;

    rc = dwarf_diename(the_die, &die_name, &err);
    if (rc == DW_DLV_ERROR)
        fatal("unable to parse dwarf diename");

    if (rc == DW_DLV_NO_ENTRY)
        return subprograms;

    rc = dwarf_attr(cu_die, DW_AT_name, &attrib, &err);
    DWARF_ASSERT(rc, err);

    if (rc != DW_DLV_NO_ENTRY) {
        rc = dwarf_formstring(attrib, &filename, &err);
        DWARF_ASSERT(rc, err);

        dwarf_dealloc(dbg, attrib, DW_DLA_ATTR);
    }

    rc = dwarf_lowpc(the_die, &lowpc, &err);
    DWARF_ASSERT(rc, err);

    rc = dwarf_highpc(the_die, &highpc, &err);
    DWARF_ASSERT(rc, err);

    /* TODO: when would these not be defined? */
    if (lowpc && highpc) {
        subprogram = malloc(sizeof(*subprogram));
        if (!subprogram)
            fatal("unable to allocate memory");
        memset(subprogram, 0, sizeof(*subprogram));

        subprogram->lowpc = lowpc;
        subprogram->highpc = highpc;
        subprogram->name = die_name;

        subprogram->next = subprograms;
        subprograms = subprogram;
    }

    return subprograms;
}

static struct dwarf_subprogram_t *read_from_cus(Dwarf_Debug dbg)
{
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die, next_die;
    int ret = DW_DLV_OK;
    int rc;
    struct dwarf_subprogram_t *subprograms = NULL;

    while (ret == DW_DLV_OK) {
        ret = dwarf_next_cu_header(
                dbg,
                &cu_header_length,
                &version_stamp,
                &abbrev_offset,
                &address_size,
                &next_cu_header,
                &err);
        DWARF_ASSERT(ret, err);

        if (ret == DW_DLV_NO_ENTRY)
            continue;

        /* TODO: If the CU can provide an address range then we can skip over
         * all the entire die if none of our addresses match */

        /* Expect the CU to have a single sibling - a DIE */
        ret = dwarf_siblingof(dbg, no_die, &cu_die, &err);
        if (ret == DW_DLV_ERROR) {
            continue;
        }
        DWARF_ASSERT(ret, err);

        /* Expect the CU DIE to have children */
        ret = dwarf_child(cu_die, &child_die, &err);
        DWARF_ASSERT(ret, err);

        next_die = child_die;

        /* Now go over all children DIEs */
        do {
            subprograms = read_cu_entry(subprograms, dbg, cu_die, child_die);

            rc = dwarf_siblingof(dbg, child_die, &next_die, &err);
            DWARF_ASSERT(rc, err);

            dwarf_dealloc(dbg, child_die, DW_DLA_DIE);

            child_die = next_die;
        } while (rc != DW_DLV_NO_ENTRY);

        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
    }

    return subprograms;
}

/* simple but too slow */
struct dwarf_subprogram_t *read_from_globals(Dwarf_Debug dbg)
{
    Dwarf_Global *globals = NULL;
    Dwarf_Signed nglobals;
    Dwarf_Off offset;
    Dwarf_Die die;
    Dwarf_Addr lowpc = 0;
    Dwarf_Addr highpc = 0;
    Dwarf_Error err;
    Dwarf_Attribute attrib = 0;
    struct dwarf_subprogram_t *subprograms = NULL;
    struct dwarf_subprogram_t *subprogram = NULL;
    char *name;
    int i;
    int ret;

    ret = dwarf_get_globals(dbg, &globals, &nglobals, &err);
    DWARF_ASSERT(ret, err);

    if (ret != DW_DLV_OK)
        fatal("unable to get dwarf globals");

    for (i = 0; i < nglobals; i++) {
        ret = dwarf_global_die_offset(globals[i], &offset, &err);
        DWARF_ASSERT(ret, err);

        /* TODO: this function does a linear search, making it pretty damn
         * slow.. see libdwarf/dwarf_die_deliv.c:_dwarf_find_CU_Context
         * for details */
        ret = dwarf_offdie(dbg, offset, &die, &err);
        DWARF_ASSERT(ret, err);

        ret = dwarf_lowpc(die, &lowpc, &err);
        DWARF_ASSERT(ret, err);

        ret = dwarf_highpc(die, &highpc, &err);
        DWARF_ASSERT(ret, err);

        /* TODO: when would these not be defined? */
        if (lowpc && highpc) {
            subprogram = malloc(sizeof(*subprogram));
            if (!subprogram)
                fatal("unable to allocate memory for subprogram");
            memset(subprogram, 0, sizeof(*subprogram));

            ret = dwarf_attr(die, DW_AT_MIPS_linkage_name, &attrib, &err);
            if (ret == DW_DLV_OK) {
                ret = dwarf_formstring(attrib, &name, &err);
                DWARF_ASSERT(ret, err);

                dwarf_dealloc(dbg, attrib, DW_DLA_ATTR);
            } else {
                ret = dwarf_globname(globals[i], &name, &err);
                DWARF_ASSERT(ret, err);
            }

            subprogram->lowpc = lowpc;
            subprogram->highpc = highpc;
            subprogram->name = name;

            subprogram->next = subprograms;
            subprograms = subprogram;
        }

        dwarf_dealloc(dbg, die, DW_DLA_DIE);
    }

    return subprograms;
}

struct dwarf_subprogram_t *subprograms_load(Dwarf_Debug dbg,
                                            enum subprograms_type_t type)
{
    struct dwarf_subprogram_t *subprograms = NULL;

    switch (type) {
        case SUBPROGRAMS_GLOBALS:
            subprograms = read_from_globals(dbg);
            break;
        case SUBPROGRAMS_CUS:
            subprograms = read_from_cus(dbg);
            break;
        default:
            fatal("unknown cache type %d", type);
    }

    return subprograms;
}

/* vim:set ts=4 sw=4 sts=4 expandtab: */
