# 顶层 Makefile — 构建所有组件

kernelver ?= $(shell uname -r)

LANDLOCK_ENABLE ?= 0
ifeq ($(LANDLOCK_ENABLE),1)
export CONFIG_LANDLOCK_ENABLE := 1
endif

.PHONY: all clean kmod user test install

all: kmod user test
	mkdir -p dist
	mv driver/dyn_sandbox.ko dyn-sandbox/dyn-sandbox dyn-sandbox-dns/dyn-sandbox-dns dist/
	@if [ -e test/seccomp_test ]; then mv test/seccomp_test dist/; fi

kmod:
	$(MAKE) -C driver kernelver=$(kernelver)

user:
	$(MAKE) -C dyn-sandbox
	$(MAKE) -C dyn-sandbox-dns HAVE_SYSTEMD=1

test: user
	@if [ -d test ]; then $(MAKE) -C test; fi

install: all
	install -d $(DESTDIR)/usr/bin
	install -d $(DESTDIR)/usr/lib/systemd/system
	install -d $(DESTDIR)/lib/modules/$(kernelver)/extra
	install -m 0755 dist/dyn-sandbox $(DESTDIR)/usr/bin/
	install -m 0755 dist/dyn-sandbox-dns $(DESTDIR)/usr/bin/
	install -m 0644 service/dyn-sandbox.service $(DESTDIR)/usr/lib/systemd/system/
	install -m 0644 dist/dyn_sandbox.ko $(DESTDIR)/lib/modules/$(kernelver)/extra/

clean:
	$(MAKE) -C driver clean
	$(MAKE) -C dyn-sandbox clean
	$(MAKE) -C dyn-sandbox-dns clean
	@if [ -d test ]; then $(MAKE) -C test clean; fi
	rm -rf dist
