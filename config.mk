VERSION = 1.0

PREFIX = /usr/local

DWARFCFLAGS =
DWARFLDFLAGS =

CFLAGS = -Wall -Werror -O2 ${DWARFCFLAGS} -DATOSL_VERSION=\"${VERSION}\"
LDFLAGS = ${DWARFLDFLAGS} -ldwarf -liberty

CC = cc

-include config.mk.local
