
#KCDB_CFLAGS:=`kcutilmgr conf -i`
#KCDB_LIBS:=`kcutilmgr conf -l`
#CFLAGS=-Wall -g3 $(KCDB_CFLAGS)
#LIBS=-lsqlite3 -lev $(KCDB_LIBS)

CFLAGS=-Wall -g3 -DEVHTTP_HANDLE_FORM
#CFLAGS=-Wall -O2 -fomit-frame-pointer -DNDEBUG
LIBS=-lpcre -lev -lpthread

OBJS=evhttp.o evhttpconn.o xerror.o xobstack.o hdrstore.o buffer.o hexdump.o form.o

TOPDIR := $(shell pwd)
LIBOBJS := $(OBJS)

export TOPDIR LIBOBJS LIBS CFLAGS

.PHONY: all clean rebuild test

all: evhttp test
rebuild: clean all

$(OBJS): %.o: %.c %.h
	$(CC) -c $(CFLAGS) $< -o $@

main.o: main.c
	$(CC) -c $(CFLAGS) $< -o $@

evhttp: main.o $(OBJS)
	$(CC) $(CFLAGS) -o evhttp main.o $(OBJS) $(LIBS)

clean:
	rm -f $(OBJS) main.o
	rm -f evhttp
	cd test && $(MAKE) clean

test:
	cd test && $(MAKE) all
