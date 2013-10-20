VERSION = 1.0

PREFIX = /usr/local

DWARFINC =
DWARFLIB =

CFLAGS = -Wall -Werror -O2 -I${DWARFINC} -DATOSL_VERSION=\"${VERSION}\"
LDFLAGS = -L${DWARFLIB} -ldwarf -liberty

CC = cc

-include config.mk.local
