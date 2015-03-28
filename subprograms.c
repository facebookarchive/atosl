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
#include <libgen.h>

#include <dwarf.h>
#include <libdwarf.h>

#include "subprograms.h"
#include "common.h"

struct atosl_cache_header_t {
    unsigned int magic;
    unsigned int version;
    unsigned int n_entries;
    unsigned int cksum;
};

struct atosl_cache_entry_t {
    Dwarf_Addr lowpc;
    Dwarf_Addr highpc;
    int namelen;
    /* char *name follows the struct */
};

unsigned int checksum(int cksum, unsigned char *data, size_t len)
{
    int  i;
    for (i = 0; i < len; ++i)
        cksum += (unsigned int)(*data++);
    return cksum;
}

/* The following function concatenates function parameters to the function name.
 in case we symbolicate a Swift compilation unit, since Swift enables mutliple overloads for the same function name */
static char* get_function_name_with_params(char *die_name, Dwarf_Die the_die, Dwarf_Debug dbg)
{
    int rc;
    Dwarf_Error err;

    /* Allocate symbol name string buffer */
    int symbol_name_buffer_length = (strlen(die_name) + 2) * 32; /* Buffer size */
    char *symbol_name = malloc(symbol_name_buffer_length);
    if (!symbol_name)
        fatal("unable to allocate memory");
    
    /* Concatenate subprogram name and " (" */
    strcpy(symbol_name, die_name);
    strcat(symbol_name, " (");
    int symbol_name_length = strlen(symbol_name); /* Actual string length */

    /* Get subprogram children */
    Dwarf_Die child_die = NULL;
    Dwarf_Die next_die;
    rc = dwarf_child(the_die, &child_die, &err);
    DWARF_ASSERT(rc, err);
    
    if (rc == DW_DLV_OK && child_die){
        do {
            /* Get child tag */
            Dwarf_Half child_tag;
            rc = dwarf_tag(child_die, &child_tag, &err);
            if (rc != DW_DLV_OK)
                fatal("unable to parse dwarf tag");
            
            /* Check if child is a parameter */
            if (child_tag == DW_TAG_formal_parameter) {
                char* param_name = 0;

                /* Get param name (child die name), ignoring the "self" parameter */
                rc = dwarf_diename(child_die, &param_name, &err);
                if (rc == DW_DLV_OK && strcmp(param_name, "self") != 0) {
                
                    /* Update actual symbol name string length */
                    symbol_name_length += strlen(param_name) + 2;
                    
                    /* Check if symbol name string buffer needs expansion */
                    if (symbol_name_length >= symbol_name_buffer_length - 1)
                        
                    /* Expand (reallocate) symbol name string buffer */
                        symbol_name = realloc(symbol_name, symbol_name_buffer_length *= 2);
                    
                    /* Concatenate param name and ", " */
                    strcat(symbol_name, param_name);
                    strcat(symbol_name, ", ");
                }
            }
            
            /* Move to next sibling (param) */
            rc = dwarf_siblingof(dbg, child_die, &next_die, &err);
            DWARF_ASSERT(rc, err);
            dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
            
            child_die = next_die;
        } while (rc != DW_DLV_NO_ENTRY);
    }

    /* Remove trailing ", " if needed */
    int len = strlen(symbol_name);
    if (symbol_name[len - 1] == ' ') {
        symbol_name[len - 1] = 0;
        symbol_name[len - 2] = 0;
    }
    
    strcat (symbol_name, ")");

    return symbol_name;
}

char* get_die_name(Dwarf_Debug dbg, Dwarf_Die the_die) {
    char* result_name = NULL;
    Dwarf_Attribute *atlist = 0;
    Dwarf_Signed atcnt = 0;
    Dwarf_Error err;
    
    dwarf_attrlist(the_die, &atlist, &atcnt, &err);
    
    int rc;
    
    for (int i = 0; i < atcnt && result_name == NULL; i++) {
        Dwarf_Half attr;
        int ares;
        
        ares = dwarf_whatattr(atlist[i], &attr, &err);
        if (ares == DW_DLV_OK) {
            switch (attr) {
                case DW_AT_specification:
                case DW_AT_abstract_origin:
                case DW_AT_type: {
                    
                    Dwarf_Off ref_off = 0;
                    Dwarf_Die ref_die = 0;
                    Dwarf_Bool is_info ;
                    is_info = dwarf_get_die_infotypes_flag(the_die);
                    int res = dwarf_global_formref(atlist[i], &ref_off, &err);
                    
                    res = dwarf_offdie_b(dbg,ref_off,is_info,&ref_die,&err);
                    
                    result_name = get_die_name(dbg, ref_die);
                    
                }
                    break;
                case DW_AT_name:
                case DW_AT_MIPS_linkage_name: {
                    char* filename = NULL;
                    
                    rc = dwarf_formstring(atlist[i], &filename, &err);
                    DWARF_ASSERT(rc, err);
                    
                    if (filename) {
                        result_name = filename;
                    }
                }
            }
        }
        dwarf_dealloc(dbg, atlist[i], DW_DLA_ATTR);
    }
    dwarf_dealloc(dbg, atlist, DW_DLA_LIST);
    return result_name;
}

/* This method walks the compilation units to find the symbols. It's faster
 * than caching the globals, but it requires a little more manual work and
 * seems to be missing C++ symbols at the moment.  Note also that it's likely
 * only faster because of how slow dwarf_offdie is. It's probably best to
 * switch to cache_globals if we fix that */

/* List a function if it's in the given DIE.
*/
static struct dwarf_subprogram_t *read_cu_entry(
        struct dwarf_subprogram_t *subprograms,
        Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die the_die, Dwarf_Unsigned language)
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
    
    die_name = get_die_name(dbg, the_die);
    
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

        char* symbol_name = die_name;
        
        /* Concatenate function params in case this is Swift */
        if (language == DW_LANG_Swift)
            symbol_name = get_function_name_with_params(die_name, the_die, dbg);
        
        subprogram->lowpc = lowpc;
        subprogram->highpc = highpc;
        subprogram->name = symbol_name;

        subprogram->next = subprograms;
        subprograms = subprogram;
    }

    return subprograms;
}


static void handle_die(
        struct dwarf_subprogram_t **subprograms,
        Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Die the_die, Dwarf_Unsigned language)
{
    int rc;
    Dwarf_Error err;
    Dwarf_Die current_die = the_die;
    Dwarf_Die child_die = NULL;
    Dwarf_Die next_die;

    do {
        *subprograms = read_cu_entry(*subprograms, dbg, cu_die, current_die, language);

        /* Recursive call handle_die with child, to continue searching within child dies */
        rc = dwarf_child(current_die, &child_die, &err);
        DWARF_ASSERT(rc, err);
        if (rc == DW_DLV_OK && child_die)
            handle_die(subprograms, dbg, cu_die, child_die, language);    

        rc = dwarf_siblingof(dbg, current_die, &next_die, &err);
        DWARF_ASSERT(rc, err);

        dwarf_dealloc(dbg, current_die, DW_DLA_DIE);

        current_die = next_die;
    } while (rc != DW_DLV_NO_ENTRY);
}

static struct dwarf_subprogram_t *read_from_cus(Dwarf_Debug dbg)
{
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Error err;
    Dwarf_Die no_die = 0, cu_die, child_die;
    int ret = DW_DLV_OK;
    struct dwarf_subprogram_t *subprograms = NULL;
    Dwarf_Unsigned language = 0;
    Dwarf_Attribute language_attr = 0;

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

        /* Get compilation unit language attribute */
        ret = dwarf_attr(cu_die, DW_AT_language, &language_attr, &err);
        DWARF_ASSERT(ret, err);
        if (ret != DW_DLV_NO_ENTRY) {
            /* Get language attribute data */
            ret = dwarf_formudata(language_attr, &language, &err);
            DWARF_ASSERT(ret, err);
            dwarf_dealloc(dbg, language_attr, DW_DLA_ATTR);
        }

        /* Expect the CU DIE to have children */
        ret = dwarf_child(cu_die, &child_die, &err);
        DWARF_ASSERT(ret, err);
        
        handle_die(&subprograms, dbg, cu_die, child_die, language);  

        dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
    }

    return subprograms;
}

static char *get_cache_filename(struct subprograms_options_t *options,
                                uint8_t uuid[UUID_LEN])
{
    int i;
    int max_dirlen  =
        MAX(strlen(getenv("HOME")) + strlen("/") + strlen(SUBPROGRAMS_CACHE_PATH),
            options->cache_dir ? strlen(options->cache_dir) : 0);
    size_t filename_len =
        max_dirlen + strlen("/") + (UUID_LEN * sizeof(char) * 2) + 1;

    char *filename = malloc(sizeof(char) * filename_len);
    memset(filename, 0, filename_len);

    /* First generate the directory */
    if (options->cache_dir)
        sprintf(filename, "%s/", options->cache_dir);
    else
        sprintf(filename, "%s/" SUBPROGRAMS_CACHE_PATH, getenv("HOME"));

    if (access(filename, F_OK) != 0) {
        if (errno == ENOENT) {
            int ret = mkdir(filename, 0777);

            if (ret < 0)
                fatal("unable to create %s: %s", filename, strerror(errno));
        }
    }

    /* Then add the filename (ascii version of uuid) */
    filename = strcat(filename, "/");
    char *p = filename + strlen(filename);
    for (i = 0; i < UUID_LEN; i++)
        p += sprintf(p, "%.02x", uuid[i]);

    return filename;
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

static struct dwarf_subprogram_t *load_subprograms(const char *filename)
{
    ssize_t ret;
    int i;
    struct atosl_cache_header_t cache_header = {0};
    struct atosl_cache_entry_t cache_entry;
    struct dwarf_subprogram_t *subprograms = NULL;
    int fd;
    unsigned int cksum = 0;

    struct dwarf_subprogram_t *subprogram;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        warning("unable to open cache for reading at %s: %s",
                filename, strerror(errno));
        goto error;
    }

    ret = _read(fd, &cache_header, sizeof(cache_header));
    if (ret < 0) {
        warning("unable to read data from cache: %s", strerror(errno));
        goto error;
    }

    if (cache_header.magic != SUBPROGRAMS_CACHE_MAGIC) {
        warning("Wrong file magic: expected %x, read %x",
                SUBPROGRAMS_CACHE_MAGIC, cache_header.magic);
        goto error;
    }

    if (cache_header.version != SUBPROGRAMS_CACHE_VERSION) {
        warning("Unable to handle cache version %d", cache_header.version);
        goto error;
    }

    for (i = 0; i < cache_header.n_entries; i++) {
        ret = _read(fd, &cache_entry, sizeof(cache_entry));
        if (ret < 0) {
            warning("unable to read data from cache: %s", strerror(errno));
            goto error;
        }
        cksum = checksum(cksum, (unsigned char *)&cache_entry, sizeof(cache_entry));

        subprogram = malloc(sizeof(*subprogram));
        if (!subprogram)
            fatal("unable to allocate memory");
        memset(subprogram, 0, sizeof(*subprogram));

        subprogram->lowpc = cache_entry.lowpc;
        subprogram->highpc = cache_entry.highpc;
        subprogram->name = malloc(sizeof(char)*cache_entry.namelen);
        ret = _read(fd, (char *)subprogram->name, cache_entry.namelen);
        if (ret < 0) {
            warning("unable to read data from cache: %s", strerror(errno));
            goto error;
        }
        cksum = checksum(cksum, (unsigned char *)subprogram->name, cache_entry.namelen);

        subprogram->next = subprograms;
        subprograms = subprogram;
    }

    close(fd);

    if (cache_header.cksum != cksum) {
        warning("Invalid checksum: expected %x, read %x",
                cache_header.cksum, cksum);
        goto error;
    }

    return subprograms;

error:
    if (fd > 0)
        close(fd);

    warning("can't read cache from %s", filename);
    return NULL;
}

static void save_subprograms(const char *filename, struct dwarf_subprogram_t *subprograms)
{
    ssize_t ret;
    off_t offset;
    unsigned int cksum = 0;
    struct atosl_cache_header_t cache_header = {
        .magic = SUBPROGRAMS_CACHE_MAGIC,
        .version = SUBPROGRAMS_CACHE_VERSION,
    };

    struct atosl_cache_entry_t cache_entry;
    int fd;

    /* We want to put the tempfile in the same directory as the final file so we
     * can assure an atomic rename.
     */
    char *tempfile =
        malloc(strlen(filename) + strlen(".") + strlen(".XXXXXX") + 1);
    char *pathbits = strdup(filename);
    char *dname = dirname(pathbits);
    /* dirname inserts a \0 where the final / was, so skip over the dname to get
     * the basename
     */
    char *basename = dname + strlen(dname) + 1;
    sprintf(tempfile, "%s/.%s.XXXXXX", dname, basename);

    fd = mkstemp(tempfile);
    if (fd < 0)
        fatal("unable to open cache for writing at %s: %s",
              tempfile, strerror(errno));

    offset = lseek(fd, sizeof(cache_header), SEEK_SET);
    if (offset < 0)
        fatal("unable to seek in cache: %s", strerror(errno));

    struct dwarf_subprogram_t *subprogram = subprograms;

    while (subprogram) {
        cache_entry.lowpc = subprogram->lowpc;
        cache_entry.highpc = subprogram->highpc;
        cache_entry.namelen = strlen(subprogram->name)+1;

        cksum = checksum(cksum, (unsigned char *)&cache_entry, sizeof(cache_entry));
        ret = _write(fd, &cache_entry, sizeof(cache_entry));
        if (ret < 0)
            fatal("unable to write data to cache: %s", strerror(errno));
        cksum = checksum(cksum, (unsigned char *)subprogram->name, cache_entry.namelen);

        ret = _write(fd, subprogram->name, cache_entry.namelen);
        if (ret < 0)
            fatal("unable to write data to cache: %s", strerror(errno));

        cache_header.n_entries++;
        subprogram = subprogram->next;
    }

    cache_header.cksum = cksum;

    offset = lseek(fd, 0, SEEK_SET);
    if (offset < 0)
        fatal("unable to seek in cache: %s", strerror(errno));

    ret = _write(fd, &cache_header, sizeof(cache_header));
    if (ret < 0)
        fatal("unable to write data to cache: %s", strerror(errno));

    close(fd);

    ret = rename(tempfile, filename);
    if (ret < 0)
        fatal("Unable to rename cache from %s to %s: %s",
              tempfile, filename, strerror(errno));

    free(tempfile);
    free(pathbits);
}

struct dwarf_subprogram_t *subprograms_load(Dwarf_Debug dbg,
                                            uint8_t uuid[UUID_LEN],
                                            enum subprograms_type_t type,
                                            struct subprograms_options_t *options)
{
    struct dwarf_subprogram_t *subprograms = NULL;
    char *filename = NULL;

    if (options->persistent) {
        filename = get_cache_filename(options, uuid);

        if (access(filename, R_OK) == 0)
            subprograms = load_subprograms(filename);
    }

    if (!subprograms) {
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

        if (options->persistent)
            save_subprograms(filename, subprograms);
    }

    if (filename)
        free(filename);

    return subprograms;
}

/* vim:set ts=4 sw=4 sts=4 expandtab: */
