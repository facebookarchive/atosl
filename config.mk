VERSION = 1.1

PREFIX = /usr/local

CFLAGS = -Wall -Werror -O2 -DATOSL_VERSION=\"${VERSION}\" -I./libdwarf/libdwarf
LDFLAGS = -L./libdwarf/libdwarf -ldwarf -liberty -lz

CC = cc

-include config.mk.local
