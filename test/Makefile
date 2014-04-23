
.PHONY: all rebuild clean

VPATH = $(TOPDIR)

CFLAGS+=-I$(TOPDIR)
LIBS+=-lcheck

COBJS=$(patsubst %.o, $(TOPDIR)/%.o, $(LIBOBJS))

all: test-buffer

test-buffer: test-buffer.c $(LIBOBJS)
	$(CC) $(CFLAGS) -o test-buffer test-buffer.c $(COBJS) $(LIBS)

clean:
	rm -f *.o
	rm -f test-buffer
