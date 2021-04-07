CC = gcc
OUT = ip-checksum-test
CFLAGS = -O3

arch = $(shell uname -m)

CHECKSUM_O = checksum.o
CFILES = $(wildcard *.c)
OBJFILES = $(CFILES:.c=.o)

ifeq ($(arch),x86_64)
SFILES = $(wildcard amd64*.s)
OBJFILES += $(SFILES:.s=.o)
CFLAGS += -DALG_AMD64
endif

$(OUT): $(OBJFILES)
	$(CC) $(CFLAGS) $(OBJFILES) -o $(OUT)

ifeq ($(arch),e2k)
$(CHECKSUM_O): %.o: %.c
	$(CC) $(CFLAGS) -faligned -c -o $@ $<
endif

clean:
	rm -f *.o $(OUT)
