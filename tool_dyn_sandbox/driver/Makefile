obj-m := dyn_sandbox.o
dyn_sandbox-objs := sandbox_main.o sandbox_net.o sandbox_file.o sandbox_landlock.o

ifdef CONFIG_LANDLOCK_ENABLE
ccflags-y += -DCONFIG_LANDLOCK_ENABLE
endif

# 内核构建目录自动探测:
#   1) Ubuntu/Debian:  /usr/lib/modules/$(uname -r)/build  (符号链接到 linux-headers-*)
#   2) openEuler/RHEL: /usr/src/kernels/$(uname -r)
# 手动指定可用: make KDIR=/path/to/kernel/build
UNR := $(shell uname -r)
KDIR ?= /usr/lib/modules/$(UNR)/build
ifeq ($(wildcard $(KDIR)/Makefile),)
    KDIR := /usr/src/kernels/$(UNR)
endif
PWD   := $(shell pwd)

all:
	@test -f "$(KDIR)/Makefile" || { echo "错误: 未找到内核构建目录 $(KDIR)"; exit 1; }
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
