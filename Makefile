CC = gcc
OUT = ip-checksum-test
CFLAGS = -O2

arch = $(shell uname -p)

CFILES = $(wildcard *.c)
OBJFILES = $(CFILES:.c=.o)

ifeq ($(arch),x86_64)
SFILES = $(wildcard amd64*.s)
OBJFILES += $(SFILES:.s=.o)
CFLAGS += -DALG_AMD64
endif

$(OUT): $(OBJFILES)
	$(CC) $(CFLAGS) $(OBJFILES) -o $(OUT)

clean:
	rm -f *.o $(OUT)

