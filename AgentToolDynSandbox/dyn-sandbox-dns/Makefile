CC     ?= gcc
CFLAGS ?= -Wall -O2
LDLIBS := -lldns

ifeq ($(HAVE_SYSTEMD),1)
    CFLAGS += -DHAVE_SYSTEMD
    LDLIBS += -lsystemd
endif

.PHONY: all clean

all: dyn-sandbox-dns

dyn-sandbox-dns: dyn-sandbox-dns.c ../driver/sandbox.h
	$(CC) $(CFLAGS) -o $@ dyn-sandbox-dns.c $(LDLIBS)

clean:
	rm -f dyn-sandbox-dns
