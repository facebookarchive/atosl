/*
 *  Copyright (c) 2013, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#undef NDEBUG
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>

#include <dwarf.h>
#include <libdwarf.h>

#include "atosl.h"
#include "subprograms.h"
#include "common.h"

#define VERSION ATOSL_VERSION

#define DWARF_ASSERT(ret, err) \
    do { \
        if (ret == DW_DLV_ERROR) { \
            fatal("dwarf_errmsg: %s", dwarf_errmsg(err)); \
        } \
    } while (0);

extern char *
cplus_demangle (const char *mangled, int options);

typedef unsigned long Dwarf_Word;

Dwarf_Unsigned
_dwarf_decode_u_leb128(Dwarf_Small * leb128,
    Dwarf_Word * leb128_length);
#define DECODE_LEB128_UWORD(ptr, value)               \
    do {                                              \
        Dwarf_Word uleblen;                           \
        value = _dwarf_decode_u_leb128(ptr,&uleblen); \
        ptr += uleblen;                               \
    } while (0)

static int debug = 0;

static const char *shortopts = "vl:o:A:gcC:VhD";
static struct option longopts[] = {
    {"verbose", no_argument, NULL, 'v'},
    {"load-address", required_argument, NULL, 'l'},
    {"no-demangle", no_argument, NULL, 'D'},
    {"dsym", required_argument, NULL, 'o'},
    {"arch", required_argument, NULL, 'A'},
    {"globals", no_argument, NULL, 'g'},
    {"no-cache", no_argument, NULL, 'c'},
    {"cache-dir", required_argument, NULL, 'C'},
    {"version", no_argument, NULL, 'V'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
};

static struct {
    const char *name;
    cpu_type_t type;
    cpu_subtype_t subtype;
} arch_str_to_type[] = {
    {"i386", CPU_TYPE_I386, CPU_SUBTYPE_X86_ALL},
    {"armv6",  CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V6},
    {"armv7",  CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7},
    {"armv7s", CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7S},
    {"arm64",  CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL}
};

struct symbol_t {
    const char *name;
    union {
        struct nlist_t sym32;
        struct nlist_64 sym64;
    } sym;
    Dwarf_Addr addr;
    int thumb:1;
};

struct function_t {
    const char *name;
    Dwarf_Addr addr;
};

/* Various addresses, parsed from the cmdline or the mach-o sections */
static struct {
    Dwarf_Addr load_address;
    int use_globals;
    int use_cache;
    const char *dsym_filename;
    cpu_type_t cpu_type;
    cpu_subtype_t cpu_subtype;
    const char *cache_dir;
    int should_demangle;
} options = {
    .load_address = LONG_MAX,
    .use_globals = 0,
    .use_cache = 1,
    .cpu_type = CPU_TYPE_ARM,
    .cpu_subtype = CPU_SUBTYPE_ARM_V7S,
    .should_demangle = 1,
};

typedef int dwarf_mach_handle;

struct dwarf_section_t;
struct dwarf_section_t {
    struct section_t mach_section;
    struct dwarf_section_t *next;
};

struct dwarf_section_64_t;
struct dwarf_section_64_t {
    struct section_64_t mach_section;
    struct dwarf_section_64_t *next;
};

static struct {
    /* Symbols from symtab */
    struct symbol_t *symlist;
    uint32_t nsymbols;
    struct dwarf_subprogram_t *subprograms;

    Dwarf_Addr intended_addr;
    Dwarf_Addr linkedit_addr;

    struct fat_arch_t arch;

    uint8_t uuid[UUID_LEN];
    uint8_t is_64;
    uint8_t is_dwarf;
} context;

typedef struct {
    dwarf_mach_handle handle;
    Dwarf_Small length_size;
    Dwarf_Small pointer_size;
    Dwarf_Endianness endianness;

    Dwarf_Unsigned section_count;
    struct dwarf_section_t *sections;
    struct dwarf_section_64_t *sections_64;
} dwarf_mach_object_access_internals_t;

void print_help(void)
{
    fprintf(stderr, "atosl %s\n", VERSION);
    fprintf(stderr, USAGE "\n");
    fprintf(stderr, "\n");
    fprintf(stderr,
            "  -o, --dsym=FILE\t\tfile to find symbols in\n");
    fprintf(stderr,
            "  -v, --verbose\t\t\tenable verbose (debug) messages\n");
    fprintf(stderr,
            "  -l, --load-address=ADDRESS\tspecify application load address\n");
    fprintf(stderr,
            "  -A, --arch=ARCH\t\tspecify architecture\n");
    fprintf(stderr,
            "  -g, --globals\t\t\tlookup symbols using global section\n");
    fprintf(stderr,
            "  -c, --no-cache\t\tdon't cache debugging information\n");
    fprintf(stderr,
            "  -D, --no-demangle\t\tdon't demangle symbols\n");
    fprintf(stderr,
            "  -V, --version\t\t\tget current version\n");
    fprintf(stderr,
            "  -h, --help\t\t\tthis help\n");
    fprintf(stderr, "\n");
}

void dwarf_error_handler(Dwarf_Error err, Dwarf_Ptr ptr)
{
    fatal("dwarf error: %s", dwarf_errmsg(err));
}

char *demangle(const char *sym)
{
    char *demangled = NULL;

    if (debug)
        fprintf(stderr, "Unmangled name: %s\n", sym);
    if (strncmp(sym, "_Z", 2) == 0)
        demangled = cplus_demangle(sym, 0);
    else if (strncmp(sym, "__Z", 3) == 0)
        demangled = cplus_demangle(sym+1, 0);

    return demangled;
}

int parse_uuid(dwarf_mach_object_access_internals_t *obj, uint32_t cmdsize)
{
    int i;
    int ret;

    ret = _read(obj->handle, context.uuid, UUID_LEN);
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "%10s ", "uuid");
        for (i = 0; i < UUID_LEN; i++) {
            fprintf(stderr, "%.02x", context.uuid[i]);
        }
        fprintf(stderr, "\n");
    }

    return 0;
}

int parse_section(dwarf_mach_object_access_internals_t *obj)
{
    int ret;
    struct dwarf_section_t *s;

    s = malloc(sizeof(*s));
    if (!s)
        fatal("unable to allocate memory");

    memset(s, 0, sizeof(*s));

    ret = _read(obj->handle, &s->mach_section, sizeof(s->mach_section));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Section\n");
        fprintf(stderr, "%10s %s\n", "sectname", s->mach_section.sectname);
        fprintf(stderr, "%10s %s\n", "segname", s->mach_section.segname);
        fprintf(stderr, "%10s 0x%.08x\n", "addr", s->mach_section.addr);
        fprintf(stderr, "%10s 0x%.08x\n", "size", s->mach_section.size);
        fprintf(stderr, "%10s %d\n", "offset", s->mach_section.offset);
        /* TODO: what is the second value here? */
        fprintf(stderr, "%10s 2^%d (?)\n", "align", s->mach_section.align);
        fprintf(stderr, "%10s %d\n", "reloff", s->mach_section.reloff);
        fprintf(stderr, "%10s %d\n", "nreloc", s->mach_section.nreloc);
        fprintf(stderr, "%10s 0x%.08x\n", "flags", s->mach_section.flags);
        fprintf(stderr, "%10s %d\n", "reserved1", s->mach_section.reserved1);
        fprintf(stderr, "%10s %d\n", "reserved2", s->mach_section.reserved2);
    }

    struct dwarf_section_t *sec = obj->sections;
    if (!sec)
        obj->sections = s;
    else {
        while (sec) {
            if (sec->next == NULL) {
                sec->next = s;
                break;
            } else {
                sec = sec->next;
            }
        }
    }

    obj->section_count++;

    return 0;
}

int parse_section_64(dwarf_mach_object_access_internals_t *obj)
{
    int ret;
    struct dwarf_section_64_t *s;

    s = malloc(sizeof(*s));
    if (!s)
        fatal("unable to allocate memory");

    memset(s, 0, sizeof(*s));

    ret = _read(obj->handle, &s->mach_section, sizeof(s->mach_section));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Section\n");
        fprintf(stderr, "%10s %s\n", "sectname", s->mach_section.sectname);
        fprintf(stderr, "%10s %s\n", "segname", s->mach_section.segname);
        fprintf(stderr, "%10s 0x%.8llx\n", "addr", (unsigned long long)s->mach_section.addr);
        fprintf(stderr, "%10s 0x%.8llx\n", "size", (unsigned long long)s->mach_section.size);
        fprintf(stderr, "%10s %d\n", "offset", s->mach_section.offset);
        /* TODO: what is the second value here? */
        fprintf(stderr, "%10s 2^%d (?)\n", "align", s->mach_section.align);
        fprintf(stderr, "%10s %d\n", "reloff", s->mach_section.reloff);
        fprintf(stderr, "%10s %d\n", "nreloc", s->mach_section.nreloc);
        fprintf(stderr, "%10s 0x%.08x\n", "flags", s->mach_section.flags);
        fprintf(stderr, "%10s %d\n", "reserved1", s->mach_section.reserved1);
        fprintf(stderr, "%10s %d\n", "reserved2", s->mach_section.reserved2);
        fprintf(stderr, "%10s %d\n", "reserved3", s->mach_section.reserved3);
    }

    struct dwarf_section_64_t *sec = obj->sections_64;
    
    if (!sec) {
        obj->sections_64 = s;
    } else {
        while (sec) {
            if (sec->next == NULL) {
                sec->next = s;
                break;
            } else {
                sec = sec->next;
            }
        }
    }

    obj->section_count++;

    return 0;
}

int parse_segment(dwarf_mach_object_access_internals_t *obj, uint32_t cmdsize)
{
    int err;
    int ret;
    struct segment_command_t segment;
    int i;

    ret = _read(obj->handle, &segment, sizeof(segment));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Segment: %s\n", segment.segname);
        fprintf(stderr, "\tvmaddr: 0x%.08x\n", segment.vmaddr);
        fprintf(stderr, "\tvmsize: %d\n", segment.vmsize);
        fprintf(stderr, "\tfileoff: 0x%.08x\n", segment.fileoff);
        fprintf(stderr, "\tfilesize: %d\n", segment.filesize);
        fprintf(stderr, "\tmaxprot: %d\n", segment.maxprot);
        fprintf(stderr, "\tinitprot: %d\n", segment.initprot);
        fprintf(stderr, "\tnsects: %d\n", segment.nsects);
        fprintf(stderr, "\tflags: %.08x\n", segment.flags);
    }

    if (strcmp(segment.segname, "__TEXT") == 0) {
        context.intended_addr = segment.vmaddr;
    }

    if (strcmp(segment.segname, "__LINKEDIT") == 0) {
        context.linkedit_addr = segment.fileoff;
    }

    if (strcmp(segment.segname, "__DWARF") == 0) {
        context.is_dwarf = 1;
    }

    for (i = 0; i < segment.nsects; i++) {
        err = parse_section(obj);
        if (err)
            fatal("unable to parse section in `%s`", segment.segname);
    }

    return 0;
}

int parse_segment_64(dwarf_mach_object_access_internals_t *obj, uint32_t cmdsize)
{
    int err;
    int ret;
    struct segment_command_64_t segment;
    int i;

    ret = _read(obj->handle, &segment, sizeof(segment));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Segment: %s\n", segment.segname);
        fprintf(stderr, "\tvmaddr: 0x%.8llx\n", (unsigned long long)segment.vmaddr);
        fprintf(stderr, "\tvmsize: %llu\n", (unsigned long long)segment.vmsize);
        fprintf(stderr, "\tfileoff: 0x%.8llx\n", (unsigned long long)segment.fileoff);
        fprintf(stderr, "\tfilesize: %llu\n", (unsigned long long)segment.filesize);
        fprintf(stderr, "\tmaxprot: %d\n", segment.maxprot);
        fprintf(stderr, "\tinitprot: %d\n", segment.initprot);
        fprintf(stderr, "\tnsects: %d\n", segment.nsects);
        fprintf(stderr, "\tflags: %.08x\n", segment.flags);
    }

    if (strcmp(segment.segname, "__TEXT") == 0) {
        context.intended_addr = segment.vmaddr;
    }

    if (strcmp(segment.segname, "__LINKEDIT") == 0) {
        context.linkedit_addr = segment.fileoff;
    }

    if (strcmp(segment.segname, "__DWARF") == 0) {
        context.is_dwarf = 1;
    }

    for (i = 0; i < segment.nsects; i++) {
        err = parse_section_64(obj);
        if (err)
            fatal("unable to parse section in `%s`", segment.segname);
    }

    return 0;
}

int parse_symtab(dwarf_mach_object_access_internals_t *obj, uint32_t cmdsize)
{
    int ret;
    off_t pos;
    int i;
    char *strtable;

    struct symtab_command_t symtab;
    struct symbol_t *current;

    ret = _read(obj->handle, &symtab, sizeof(symtab));
    if (ret < 0)
        fatal_file(ret);

    if (debug) {
        fprintf(stderr, "Symbol\n");
        fprintf(stderr, "%10s %.08x\n", "symoff", symtab.symoff);
        fprintf(stderr, "%10s %d\n", "nsyms", symtab.nsyms);
        fprintf(stderr, "%10s %.08x\n", "stroff", symtab.stroff);
        fprintf(stderr, "%10s %d\n", "strsize", symtab.strsize);
    }

    strtable = malloc(symtab.strsize);
    if (!strtable)
        fatal("unable to allocate memory");

    pos = lseek(obj->handle, 0, SEEK_CUR);
    if (pos < 0)
        fatal("error seeking: %s", strerror(errno));

    ret = lseek(obj->handle, context.arch.offset+symtab.stroff, SEEK_SET);
    if (ret < 0)
        fatal("error seeking: %s", strerror(errno));

    ret = _read(obj->handle, strtable, symtab.strsize);
    if (ret < 0)
        fatal_file(ret);

    ret = lseek(obj->handle, context.arch.offset+symtab.symoff, SEEK_SET);
    if (ret < 0)
        fatal("error seeking: %s", strerror(errno));

    context.nsymbols = symtab.nsyms;
    context.symlist = malloc(sizeof(struct symbol_t) * symtab.nsyms);
    if (!context.symlist)
        fatal("unable to allocate memory");
    current = context.symlist;

    for (i = 0; i < symtab.nsyms; i++) {
        ret = _read(obj->handle, context.is_64 ? (void*)&current->sym.sym64 : (void*)&current->sym.sym32, context.is_64 ? sizeof(current->sym.sym64) : sizeof(current->sym.sym32));
        if (ret < 0)
            fatal_file(ret);

        if (context.is_64 ? current->sym.sym64.n_un.n_strx : current->sym.sym32.n_un.n_strx) {
            if ((context.is_64 ? current->sym.sym64.n_un.n_strx : current->sym.sym32.n_un.n_strx) > symtab.strsize)
                fatal("str offset (%d) greater than strsize (%d)",
                      (context.is_64 ? current->sym.sym64.n_un.n_strx : current->sym.sym32.n_un.n_strx), symtab.strsize);
            current->name = strtable+(context.is_64 ? current->sym.sym64.n_un.n_strx : current->sym.sym32.n_un.n_strx);
        }

        current++;
    }

    ret = lseek(obj->handle, pos, SEEK_SET);
    if (ret < 0)
        fatal("error seeking: %s", strerror(errno));

    return 0;
}

static int compare_symbols(const void *a, const void *b)
{
    struct symbol_t *sym_a = (struct symbol_t *)a;
    struct symbol_t *sym_b = (struct symbol_t *)b;
    return sym_a->addr - sym_b->addr;
}

void print_symbol(const char *symbol, unsigned offset)
{
    char *demangled = options.should_demangle ? demangle(symbol) : NULL;
    const char *name = demangled ? demangled : symbol;

    if (name[0] == '_')
        name++;

    printf("%s%s (in %s) + %d\n",
            name,
            demangled ? "()" : "",
            basename((char *)options.dsym_filename),
            offset);

    if (demangled)
        free(demangled);
}

/* Print symbol name based on stabs information.
 * Currently only handles functions (N_FUN stabs)
 *
 * See README.stabs for stabs format information.
 *
 * Here we find pairs of N_FUN stabs. The first has the name of the function and its starting address;
 * the second has its size.
 *
 * We could also symbolicate global and static symbols (N_GSYM and N_STSYM) here,
 * but it's not necessary to do so since they'll be picked up by the generic symbol table
 * search later in this function.
 *
 * Return 1 if a symbol corresponding to search_addr was found; 0 otherwise.
 */
int handle_stabs_symbol(int is_fun_stab, Dwarf_Addr search_addr, const struct symbol_t *symbol)
{
    /* These are static since they need to persist across pairs of symbols. */
    static const char *last_fun_name = NULL;
    static Dwarf_Addr last_addr;

    if (is_fun_stab) {  
        if (last_fun_name) { /* if this is non-null, the last symbol was an N_FUN stab as well. */
            if (debug)
                fprintf(stderr, "\t\tSecond consecutive N_FUN symbol. Function size: %llu (0x%llx)\n",
                        symbol->addr, symbol->addr);
            if (last_addr <= search_addr
                    && search_addr < last_addr + symbol->addr) {
                print_symbol(last_fun_name, (unsigned int)(search_addr - last_addr));
                return 1;
            } else if (debug)
                fprintf(stderr, "\t\tNot printing symbol %s; 0x%llx not in the interval [0x%llx 0x%llx).\n",
                        last_fun_name, search_addr, last_addr, last_addr + symbol->addr);
            last_fun_name = NULL;
        } else { /* last_fun_name is null, so this is the first N_FUN in (possibly) a pair. */
            last_fun_name = symbol->name;
            if (debug)
                fprintf(stderr, "\t\tFirst consecutive N_FUN symbol. Function name: %s; addr: 0x%llx\n",
                        symbol->name, symbol->addr);
        }
    } else {
        if (debug && last_fun_name) {
            fprintf(stderr, "%s", "\t\tN_FUN symbol not part of a pair! Ignoring.\n");
            fprintf(stderr, "Name: %s, addr: 0x%llx (%llu)\n", last_fun_name, last_addr, last_addr);
        }
        last_fun_name = NULL;
    }
    last_addr = symbol->addr;
    return 0;
}

int find_and_print_symtab_symbol(Dwarf_Addr slide, Dwarf_Addr addr)
{
    union {
        struct nlist_t nlist32;
        struct nlist_64 nlist64;
    } nlist;
    struct symbol_t *current;
    int found = 0;

    int i;
    int is_stab;
    uint8_t type;

    addr = addr - slide;
    current = context.symlist;

    for (i = 0; i < context.nsymbols; i++) {

        memcpy(context.is_64 ? (void*)&nlist.nlist64 : (void*)&nlist.nlist32, context.is_64 ? (void*)&current->sym.sym64 : (void*)&current->sym.sym32, context.is_64 ? sizeof(current->sym.sym64) : sizeof(current->sym.sym32));
        current->thumb = ((context.is_64 ? nlist.nlist64.n_desc : nlist.nlist32.n_desc) & N_ARM_THUMB_DEF) ? 1 : 0;

        current->addr = context.is_64 ? nlist.nlist64.n_value : nlist.nlist32.n_value;
        type = context.is_64 ? nlist.nlist64.n_type : nlist.nlist32.n_type;
        is_stab = type & N_STAB;
        if (debug) {
            fprintf(stderr, "\t\tname: %s\n", current->name);
            fprintf(stderr, "\t\tn_un.n_un.n_strx: %d\n", context.is_64 ? nlist.nlist64.n_un.n_strx : nlist.nlist32.n_un.n_strx);
            fprintf(stderr, "\t\traw n_type: 0x%x\n", context.is_64 ? nlist.nlist64.n_type : nlist.nlist32.n_type);
            fprintf(stderr, "\t\tn_type: ");
            if (is_stab)
                fprintf(stderr, "N_STAB ");
            if ((context.is_64 ? nlist.nlist64.n_type : nlist.nlist32.n_type) & N_PEXT)
                fprintf(stderr, "N_PEXT ");
            if ((context.is_64 ? nlist.nlist64.n_type : nlist.nlist32.n_type) & N_EXT)
                fprintf(stderr, "N_EXT ");
            fprintf(stderr, "\n");

            fprintf(stderr, "\t\tType: ");
            switch (type & N_TYPE) {
                case 0: fprintf(stderr, "U "); break;
                case N_ABS: fprintf(stderr, "A "); break;
                case N_SECT: fprintf(stderr, "S "); break;
                case N_INDR: fprintf(stderr, "I "); break;
            }

            fprintf(stderr, "\n");

            fprintf(stderr, "\t\tn_sect: %d\n", context.is_64 ? nlist.nlist64.n_sect : nlist.nlist32.n_sect);
            fprintf(stderr, "\t\tn_desc: %d\n", context.is_64 ? nlist.nlist64.n_desc : nlist.nlist32.n_desc);
            fprintf(stderr, "\t\tn_value: 0x%llx\n", (unsigned long long)(context.is_64 ? nlist.nlist64.n_value : nlist.nlist32.n_value));
            fprintf(stderr, "\t\taddr: 0x%llx\n", current->addr);
        }

        if (handle_stabs_symbol(is_stab && type == N_FUN, addr, current))
            return DW_DLV_OK;

        current++;

        if (debug)
            fprintf(stderr, "\n");
    }

    qsort(context.symlist, context.nsymbols, sizeof(*current), compare_symbols);
    current = context.symlist;

    for (i = 0; i < context.nsymbols; i++) {
        if (current->addr > addr) {
            if (i < 1) {
                /* Someone is asking about a symbol that comes before the first
                 * one we know about. In that case we don't have a match for
                 * them */
                break;
            }

            struct symbol_t *prev = (current - 1);
            print_symbol(prev->name, (unsigned int)(addr - prev->addr));
            found = 1;
            break;
        }
        current++;
    }

    return found ? DW_DLV_OK : DW_DLV_NO_ENTRY;
}

int parse_command(
    dwarf_mach_object_access_internals_t *obj,
    struct load_command_t load_command)
{
    int ret = 0;
    int cmdsize;

    switch (load_command.cmd) {
        case LC_UUID:
            ret = parse_uuid(obj, load_command.cmdsize);
            break;
        case LC_SEGMENT:
            ret = parse_segment(obj, load_command.cmdsize);
            break;
        case LC_SEGMENT_64:
            ret = parse_segment_64(obj, load_command.cmdsize);
            break;
        case LC_SYMTAB:
            ret = parse_symtab(obj, load_command.cmdsize);
            break;
        default:
            if (debug)
                fprintf(stderr, "Warning: unhandled command: 0x%x\n",
                                load_command.cmd);
            /* Fallthrough */
        case LC_PREPAGE:
            cmdsize = load_command.cmdsize - sizeof(load_command);
            ret = lseek(obj->handle, cmdsize, SEEK_CUR);
            if (ret < 0)
                fatal("error seeking: %s", strerror(errno));
            break;
    }

    return ret;
}

static int dwarf_mach_object_access_internals_init(
        dwarf_mach_handle handle,
        void *obj_in,
        int *error)
{
    int ret;
    struct mach_header_t header;
    struct load_command_t load_command;
    int i;

    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;

    obj->handle = handle;
    obj->length_size = 4;
    obj->pointer_size = 4;
    obj->endianness = DW_OBJECT_LSB;
    obj->sections = NULL;
    obj->sections_64 = NULL;

    ret = _read(obj->handle, &header, sizeof(header));
    if (ret < 0)
        fatal_file(ret);
    
    /* Need to skip 4 bytes of the reserved field of mach_header_64  */
    if (header.cputype == CPU_TYPE_ARM64 && header.cpusubtype == CPU_SUBTYPE_ARM64_ALL) {
        context.is_64 = 1;
        ret = lseek(obj->handle, sizeof(uint32_t), SEEK_CUR);
        if (ret < 0)
            fatal_file(ret);
    }

    if (debug) {
        fprintf(stderr, "Mach Header:\n");
        fprintf(stderr, "\tCPU Type: %d\n", header.cputype);
        fprintf(stderr, "\tCPU Subtype: %d\n", header.cpusubtype);
        fprintf(stderr, "\tFiletype: %d\n", header.filetype);
        fprintf(stderr, "\tNumber of Cmds: %d\n", header.ncmds);
        fprintf(stderr, "\tSize of commands: %d\n", header.sizeofcmds);
        fprintf(stderr, "\tFlags: %.08x\n", header.flags);
    }

    switch (header.filetype) {
        case MH_DSYM:
            if (debug)
                fprintf(stderr, "File type: debug file\n");
            break;
        case MH_DYLIB:
            if (debug)
                fprintf(stderr, "File type: dynamic library\n");
            break;
        case MH_DYLIB_STUB:
            if (debug)
                fprintf(stderr, "File type: dynamic library stub\n");
            break;
        case MH_EXECUTE:
            if (debug)
                fprintf(stderr, "File type: executable file\n");
            break;
        default:
            fatal("unsupported file type: 0x%x", header.filetype);
            assert(0);
    }

    for (i = 0; i < header.ncmds; i++) {
        ret = _read(obj->handle, &load_command, sizeof(load_command));
        if (ret < 0)
            fatal_file(ret);

        if (debug) {
            fprintf(stderr, "Load Command %d\n", i);
            fprintf(stderr, "%10s %x\n", "cmd", load_command.cmd);
            fprintf(stderr, "%10s %d\n", "cmdsize", load_command.cmdsize);
        }

        ret = parse_command(obj, load_command);
        if (ret < 0)
            fatal("unable to parse command %x", load_command.cmd);
    }

    return DW_DLV_OK;
}

static Dwarf_Endianness dwarf_mach_object_access_get_byte_order(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->endianness;
}

static Dwarf_Unsigned dwarf_mach_object_access_get_section_count(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->section_count;
}

static int dwarf_mach_object_access_get_section_info(
        void *obj_in,
        Dwarf_Half section_index,
        Dwarf_Obj_Access_Section *ret_scn,
        int *error)
{
    int i;
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;

    if (section_index >= obj->section_count) {
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }
    
    if (obj->sections_64) {
        struct dwarf_section_64_t *sec = obj->sections_64;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }
        sec->mach_section.sectname[1] = '.';
        ret_scn->size = sec->mach_section.size;
        ret_scn->addr = sec->mach_section.addr;
        ret_scn->name = sec->mach_section.sectname+1;
    } else {
        struct dwarf_section_t *sec = obj->sections;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }
        sec->mach_section.sectname[1] = '.';
        ret_scn->size = sec->mach_section.size;
        ret_scn->addr = sec->mach_section.addr;
        ret_scn->name = sec->mach_section.sectname+1;
    }
    if (strcmp(ret_scn->name, ".debug_pubnames__DWARF") == 0)
        ret_scn->name = ".debug_pubnames";

    ret_scn->link = 0; /* rela section or from symtab to strtab */
    ret_scn->entrysize = 0;

    return DW_DLV_OK;
}

static int dwarf_mach_object_access_load_section(
        void *obj_in,
        Dwarf_Half section_index,
        Dwarf_Small **section_data,
        int *error)
{
    void *addr;
    int i;
    int ret;

    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;

    if (section_index >= obj->section_count) {
        *error = DW_DLE_MDE;
        return DW_DLV_ERROR;
    }

    if (obj->sections_64) {
        struct dwarf_section_64_t *sec = obj->sections_64;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }
        addr = malloc(sec->mach_section.size);
        if (!addr)
            fatal("unable to allocate memory");
        ret = lseek(obj->handle, context.arch.offset + sec->mach_section.offset, SEEK_SET);
        if (ret < 0)
            fatal("error seeking: %s", strerror(errno));
        ret = _read(obj->handle, addr, sec->mach_section.size);
        if (ret < 0)
            fatal_file(ret);

    } else {
        struct dwarf_section_t *sec = obj->sections;
        for (i = 0; i < section_index; i++) {
            sec = sec->next;
        }
        addr = malloc(sec->mach_section.size);
        if (!addr)
            fatal("unable to allocate memory");
        ret = lseek(obj->handle, context.arch.offset + sec->mach_section.offset, SEEK_SET);
        if (ret < 0)
            fatal("error seeking: %s", strerror(errno));
        ret = _read(obj->handle, addr, sec->mach_section.size);
        if (ret < 0)
            fatal_file(ret);
        
    }
    *section_data = addr;

    return DW_DLV_OK;
}

static int dwarf_mach_object_relocate_a_section(
        void *obj_in,
        Dwarf_Half section_index,
        Dwarf_Debug dbg,
        int *error)
{
    return DW_DLV_NO_ENTRY;
}

static Dwarf_Small dwarf_mach_object_access_get_length_size(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->length_size;
}

static Dwarf_Small dwarf_mach_object_access_get_pointer_size(void *obj_in)
{
    dwarf_mach_object_access_internals_t *obj =
        (dwarf_mach_object_access_internals_t *)obj_in;
    return obj->pointer_size;
}

static const struct Dwarf_Obj_Access_Methods_s
  dwarf_mach_object_access_methods = {
    dwarf_mach_object_access_get_section_info,
    dwarf_mach_object_access_get_byte_order,
    dwarf_mach_object_access_get_length_size,
    dwarf_mach_object_access_get_pointer_size,
    dwarf_mach_object_access_get_section_count,
    dwarf_mach_object_access_load_section,
    dwarf_mach_object_relocate_a_section
};


void dwarf_mach_object_access_init(
        dwarf_mach_handle handle,
        Dwarf_Obj_Access_Interface **ret_obj,
        int *err)
{
    int res = 0;
    dwarf_mach_object_access_internals_t *internals = NULL;
    Dwarf_Obj_Access_Interface *intfc = NULL;

    internals = malloc(sizeof(*internals));
    if (!internals)
        fatal("unable to allocate memory");

    memset(internals, 0, sizeof(*internals));
    res = dwarf_mach_object_access_internals_init(handle, internals, err);
    if (res != DW_DLV_OK)
        fatal("error initializing dwarf internals");

    intfc = malloc(sizeof(Dwarf_Obj_Access_Interface));
    if (!intfc)
        fatal("unable to allocate memory");

    intfc->object = internals;
    intfc->methods = &dwarf_mach_object_access_methods;

    *ret_obj = intfc;
}

void dwarf_mach_object_access_finish(Dwarf_Obj_Access_Interface *obj)
{
    if (!obj)
        return;

    if (obj->object)
        free(obj->object);
    free(obj);
}

struct dwarf_subprogram_t *lookup_symbol(Dwarf_Addr addr)
{
    struct dwarf_subprogram_t *subprogram = context.subprograms;

    while (subprogram) {
        if ((addr >= subprogram->lowpc) &&
            (addr < subprogram->highpc)) {
            return subprogram;
        }

        subprogram = subprogram->next;
    }

    return NULL;
}

int print_subprogram_symbol(Dwarf_Addr slide, Dwarf_Addr addr)
{
    char *demangled = NULL;

    addr -= slide;

    struct dwarf_subprogram_t *match = lookup_symbol(addr);

    if (match) {
        demangled = options.should_demangle ? demangle(match->name) : NULL;
        printf("%s (in %s) + %d\n",
               demangled ?: match->name,
               basename((char *)options.dsym_filename),
               (unsigned int)(addr - match->lowpc));
        if (demangled)
            free(demangled);

    }

    return match ? 0 : -1;
}

int print_dwarf_symbol(Dwarf_Debug dbg, Dwarf_Addr slide, Dwarf_Addr addr)
{
    static Dwarf_Arange *arange_buf = NULL;
    Dwarf_Line *linebuf = NULL;
    Dwarf_Signed linecount = 0;
    Dwarf_Off cu_die_offset = 0;
    Dwarf_Die cu_die = NULL;
    Dwarf_Unsigned segment = 0;
    Dwarf_Unsigned segment_entry_size = 0;
    Dwarf_Addr start = 0;
    Dwarf_Unsigned length = 0;
    Dwarf_Arange arange;
    static Dwarf_Signed count;
    int ret;
    Dwarf_Error err;
    int i;
    int found = 0;

    addr -= slide;

    if (!arange_buf) {
        ret = dwarf_get_aranges(dbg, &arange_buf, &count, &err);
        DWARF_ASSERT(ret, err);
    }

    ret = dwarf_get_arange(arange_buf, count, addr, &arange, &err);
    DWARF_ASSERT(ret, err);

    if (ret == DW_DLV_NO_ENTRY)
        return ret;

    ret = dwarf_get_arange_info_b(
            arange,
            &segment,
            &segment_entry_size,
            &start,
            &length,
            &cu_die_offset,
            &err);
    DWARF_ASSERT(ret, err);

    ret = dwarf_offdie(dbg, cu_die_offset, &cu_die, &err);
    DWARF_ASSERT(ret, err);

    /* ret = dwarf_print_lines(cu_die, &err, &errcnt); */
    /* DWARF_ASSERT(ret, err); */

    ret = dwarf_srclines(cu_die, &linebuf, &linecount, &err);
    DWARF_ASSERT(ret, err);

    for (i = 0; i < linecount; i++) {
        Dwarf_Line prevline;
        Dwarf_Line nextline;
        Dwarf_Line line = linebuf[i];

        Dwarf_Addr lineaddr;
        Dwarf_Addr lowaddr;
        Dwarf_Addr highaddr;

        ret = dwarf_lineaddr(line, &lineaddr, &err);
        DWARF_ASSERT(ret, err);

        if (i > 0) {
            prevline = linebuf[i-1];
            ret = dwarf_lineaddr(prevline, &lowaddr, &err);
            DWARF_ASSERT(ret, err);
            lowaddr += 1;
        } else {
            lowaddr = lineaddr;
        }

        if (i < linecount - 1) {
            nextline = linebuf[i+1];
            ret = dwarf_lineaddr(nextline, &highaddr, &err);
            DWARF_ASSERT(ret, err);
            highaddr -= 1;
        } else {
            highaddr = lineaddr;
        }

        if ((addr >= lowaddr) && (addr <= highaddr)) {
            char *filename;
            Dwarf_Unsigned lineno;
            char *diename;
            char *demangled;
            struct dwarf_subprogram_t *symbol;
            const char *name;

            ret = dwarf_linesrc(line, &filename, &err);
            DWARF_ASSERT(ret, err);

            ret = dwarf_lineno(line, &lineno, &err);
            DWARF_ASSERT(ret, err);

            ret = dwarf_diename(cu_die, &diename, &err);
            DWARF_ASSERT(ret, err);

            symbol = lookup_symbol(addr);

            name = symbol ? symbol->name : "(unknown)";

            demangled = options.should_demangle ? demangle(name) : NULL;

            printf("%s (in %s) (%s:%d)\n",
                   demangled ? demangled : name,
                   basename((char *)options.dsym_filename),
                   basename(filename), (int)lineno);

            found = 1;

            if (demangled)
                free(demangled);

            dwarf_dealloc(dbg, diename, DW_DLA_STRING);
            dwarf_dealloc(dbg, filename, DW_DLA_STRING);

            break;
        }
    }

    dwarf_dealloc(dbg, arange, DW_DLA_ARANGE);
    dwarf_srclines_dealloc(dbg, linebuf, linecount);

    return found ? DW_DLV_OK : DW_DLV_NO_ENTRY;
}

int main(int argc, char *argv[]) {
    int fd;
    int ret;
    int i;
    Dwarf_Debug dbg = NULL;
    Dwarf_Error err;
    int derr = 0;
    Dwarf_Obj_Access_Interface *binary_interface = NULL;
    Dwarf_Ptr errarg = NULL;
    int option_index;
    int c;
    int found = 0;
    uint32_t magic;
    cpu_type_t cpu_type = -1;
    cpu_subtype_t cpu_subtype = -1;
    Dwarf_Addr address;

    memset(&context, 0, sizeof(context));

    while ((c = getopt_long(argc, argv, shortopts, longopts, &option_index))
            >= 0) {
        switch (c) {
            case 'l':
                errno = 0;
                address = strtol(optarg, (char **)NULL, 16);
                if (errno != 0)
                    fatal("invalid load address: `%s': %s", optarg, strerror(errno));
                options.load_address = address;
                break;
            case 'o':
                options.dsym_filename = optarg;
                break;
            case 'A':
                for (i = 0; i < NUMOF(arch_str_to_type); i++) {
                    if (strcmp(arch_str_to_type[i].name, optarg) == 0) {
                        cpu_type = arch_str_to_type[i].type;
                        cpu_subtype = arch_str_to_type[i].subtype;
                        break;
                    }
                }
                if ((cpu_type < 0) && (cpu_subtype < 0))
                    fatal("unsupported architecture `%s'", optarg);
                options.cpu_type = cpu_type;
                options.cpu_subtype = cpu_subtype;
                break;
            case 'v':
                debug = 1;
                break;
            case 'g':
                options.use_globals = 1;
                break;
            case 'c':
                options.use_cache = 0;
                break;
            case 'C':
                options.cache_dir = optarg;
                break;
            case 'D':
                options.should_demangle = 0;
                break;
            case 'V':
                fprintf(stderr, "atosl %s\n", VERSION);
                exit(EXIT_SUCCESS);
            case '?':
                print_help();
                exit(EXIT_FAILURE);
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
            default:
                fatal("unhandled option");
        }
    }

    if (!options.dsym_filename)
        fatal("no filename specified with -o");

    fd = open(options.dsym_filename, O_RDONLY);
    if (fd < 0)
        fatal("unable to open `%s': %s",
              options.dsym_filename,
              strerror(errno));

    ret = _read(fd, &magic, sizeof(magic));
    if (ret < 0)
        fatal_file(fd);

    if (magic == FAT_CIGAM) {
        /* Find the architecture we want.. */
        uint32_t nfat_arch;

        ret = _read(fd, &nfat_arch, sizeof(nfat_arch));
        if (ret < 0)
            fatal_file(fd);

        nfat_arch = ntohl(nfat_arch);
        for (i = 0; i < nfat_arch; i++) {
            ret = _read(fd, &context.arch, sizeof(context.arch));
            if (ret < 0)
                fatal("unable to read arch struct");

            context.arch.cputype = ntohl(context.arch.cputype);
            context.arch.cpusubtype = ntohl(context.arch.cpusubtype);
            context.arch.offset = ntohl(context.arch.offset);

            if ((context.arch.cputype == options.cpu_type) &&
                (context.arch.cpusubtype == options.cpu_subtype)) {
                /* good! */
                ret = lseek(fd, context.arch.offset, SEEK_SET);
                if (ret < 0)
                    fatal("unable to seek to arch (offset=%ld): %s",
                          context.arch.offset, strerror(errno));

                ret = _read(fd, &magic, sizeof(magic));
                if (ret < 0)
                    fatal_file(fd);

                found = 1;
                break;
            } else {
                /* skip */
                if (debug) {
                    fprintf(stderr, "Skipping arch: %x %x\n",
                            context.arch.cputype, context.arch.cpusubtype);
                }
            }
        }
    } else {
        found = 1;
    }

    if (!found)
        fatal("no valid architectures found");

    if (magic != MH_MAGIC && magic != MH_MAGIC_64)
      fatal("invalid magic for architecture");

    if (argc <= optind)
        fatal_usage("no addresses specified");

    dwarf_mach_object_access_init(fd, &binary_interface, &derr);
    assert(binary_interface);

    if (options.load_address == LONG_MAX)
        options.load_address = context.intended_addr;

    ret = dwarf_object_init(binary_interface,
                            dwarf_error_handler,
                            errarg, &dbg, &err);
    DWARF_ASSERT(ret, err);

    /* If there is dwarf info we'll use that to parse, otherwise we'll use the
     * symbol table */
    if (context.is_dwarf && ret == DW_DLV_OK) {

        struct subprograms_options_t opts = {
            .persistent = options.use_cache,
            .cache_dir = options.cache_dir,
        };

        context.subprograms =
            subprograms_load(dbg,
                             context.uuid,
                             options.use_globals ? SUBPROGRAMS_GLOBALS :
                                                   SUBPROGRAMS_CUS,
                             &opts);

        for (i = optind; i < argc; i++) {
            Dwarf_Addr addr;
            errno = 0;
            addr = strtol(argv[i], (char **)NULL, 16);
            if (errno != 0)
                fatal("invalid address: `%s': %s", argv[i], strerror(errno));
            ret = print_dwarf_symbol(dbg,
                                 options.load_address - context.intended_addr,
                                 addr);
            if (ret != DW_DLV_OK) {
                derr = print_subprogram_symbol(
                         options.load_address - context.intended_addr, addr);
            }

            if ((ret != DW_DLV_OK) && derr) {
                printf("%s\n", argv[i]);
            }
        }

        dwarf_mach_object_access_finish(binary_interface);

        ret = dwarf_object_finish(dbg, &err);
        DWARF_ASSERT(ret, err);
    } else {
        for (i = optind; i < argc; i++) {
            Dwarf_Addr addr;
            errno = 0;
            addr = strtol(argv[i], (char **)NULL, 16);
            if (errno != 0)
                fatal("invalid address address: `%s': %s", optarg, strerror(errno));
            ret = find_and_print_symtab_symbol(
                    options.load_address - context.intended_addr,
                    addr);

            if (ret != DW_DLV_OK)
                printf("%s\n", argv[i]);
        }
    }

    close(fd);

    return 0;
}

/* vim:set ts=4 sw=4 sts=4 expandtab: */
