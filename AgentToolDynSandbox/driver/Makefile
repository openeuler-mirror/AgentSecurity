obj-m := dyn_sandbox.o
dyn_sandbox-objs := sandbox_main.o sandbox_net.o sandbox_file.o sandbox_landlock.o

ifdef CONFIG_LANDLOCK_ENABLE
ccflags-y += -DCONFIG_LANDLOCK_ENABLE
endif

kernelver ?= $(shell uname -r)
KDIR ?= /lib/modules/$(kernelver)/build

# M 用 $(CURDIR) 而不是 $(PWD)
all:
	@test -f "$(KDIR)/Makefile" || { echo "错误: 未找到内核构建目录 $(KDIR)"; exit 1; }
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	rm -rf .*.cmd *.o *.ko *.mod *.mod.c Module.symvers modules.order .tmp_versions Module.markers

.PHONY: all clean
