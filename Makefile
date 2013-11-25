# 
#	Makefile
CFLAGS=-O2 -Wall -ggdb3 -I./lorcon_install/include
LDFLAGS=-L./lorcon_install/lib -Wl,-rpath=./lorcon_install/lib -lorcon2 -lpthread -lpcap

CC=gcc
OBJ = logger.o lrc.o
TARGET = lrc
RM = rm -f

all: $(TARGET)
	@echo

$(TARGET): $(OBJ)
	$(CC) ${LDFLAGS} -o $@ $(OBJ)

clean:
	$(RM) $(OBJ) $(TARGET) *~
