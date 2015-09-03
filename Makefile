# 
#	Makefile
HAVE_PYTHON=1
DEBUG=1

CFLAGS=-Wall
LDFLAGS=-lpthread -lpcap -lpcre -lnet -lnl-genl-3 -lnl-3 -lcrypto
CC=gcc
LD=ldd

OBJ = logger.o tqueue.o ap.o lrc.o matchers.o crypto/crypto.o $(OSD)/lib$(OSD).a

OSD = osdep
LIBOSD = $(OSD)/lib$(OSD).so

ifeq ($(HAVE_PYTHON),1)
	CFLAGS+=-DHAVE_PYTHON
	LDFLAGS+=-lpython2.7
endif

ifeq ($(DEBUG),1)
	CFLAGS+=-ggdb3
endif

all: osd lrc
	@echo

osd:
	$(MAKE) -C $(OSD)

$(LIBOSD):
	$(MAKE) -C $(OSD)

lrc: $(OBJ)
	$(CC) -o $@ $(OBJ) ${LDFLAGS} 

clean:
	rm -f $(OBJ) lrc *~
	$(MAKE) -C $(OSD) clean

distclean: clean
