
KCDB_CFLAGS:=`kcutilmgr conf -i`
KCDB_LIBS:=`kcutilmgr conf -l`
#CFLAGS=-Wall -g3 $(KCDB_CFLAGS)
#LIBS=-lsqlite3 -lev $(KCDB_LIBS)

CFLAGS=-Wall -g3
LIBS=-lev

OBJS=evhttp.o xerror.o xobstack.o hdrstore.o

all: evhttp
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
