CC       := gcc
CFLAGS   := -static -O2 -Wall -Wextra

TEST_BIN := seccomp_test
TEST_SRC := seccomp_test.c

INSTALL_DIR := /usr/local/bin

.PHONY: all clean install

all: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $<

install: all
	install -m 755 $(TEST_BIN) $(INSTALL_DIR)/

clean:
	rm -f $(TEST_BIN)
