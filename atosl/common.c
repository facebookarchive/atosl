/*
 *  Copyright (c) 2013, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "common.h"

void common_fatal(const char *file, int lineno, const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    fprintf(stderr, "atosl: %s:%d: ", file, lineno);
    vfprintf(stderr, format, vargs);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

void common_fatal_usage(const char *file, int lineno, const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    fprintf(stderr, "atosl: %s:%d ", file, lineno);
    vfprintf(stderr, format, vargs);
    fprintf(stderr, "\n");
    fprintf(stderr, USAGE "\n");
    fprintf(stderr, "\n\n");
    fprintf(stderr, "Try `atosl --help` for more options.\n");
    exit(EXIT_FAILURE);
}

void common_fatal_file(const char *file, int lineno, int ret)
{
    if (ret == -1)
        common_fatal(file, lineno, "unable to read data: %s", strerror(errno));
    else
        common_fatal(file, lineno, "too few bytes read from file");
}

void common_warning(const char *file, int lineno, const char *format, ...)
{
    va_list vargs;
    va_start(vargs, format);
    fprintf(stderr, "atosl: warning: %s:%d: ", file, lineno);
    vfprintf(stderr, format, vargs);
    fprintf(stderr, "\n");
}
