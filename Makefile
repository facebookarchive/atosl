include config.mk

SRCS := atosl.c subprograms.c common.c
HDRS := atosl.h subprograms.h common.h

TARGET := atosl

OBJS := ${SRCS:.c=.o}
DEPS := ${SRCS:.c=.dep}

DIST := ${TARGET}-${VERSION}

.PHONY: all clean distclean dist install uninstall

all:: ${TARGET}

${TARGET}: ${OBJS}
	    ${CC} -o $@ $^ ${LDFLAGS}

${OBJS}: %.o: %.c %.dep ${HDRS} config.mk $(wildcard config.mk.local)
	    ${CC} ${CFLAGS} -o $@ -c $<

${DEPS}: %.dep: %.c Makefile
	    ${CC} ${CFLAGS} -MM $< > $@

clean:
	    -rm -f *~ *.o *.dep ${TARGET} ${DIST}.tar.gz

dist: clean
	mkdir -p ${DIST}
	cp -R LICENSE PATENTS Makefile README.md config.mk ${SRCS} ${HDRS} ${DIST}
	tar -cf ${DIST}.tar ${DIST}
	gzip ${DIST}.tar
	rm -rf ${DIST}

install: all
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f atosl ${DESTDIR}${PREFIX}/bin
	chmod 755 ${DESTDIR}${PREFIX}/bin/atosl

uninstall:
	rm -f ${DESTDIR}${PREFIX}/bin/atosl

distclean:: clean
