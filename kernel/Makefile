obj-m += ihisi_diag.o

# CachyOS 内核用 clang 构建，gcc 编不了（-mllvm 等 LLVM 专属选项）。
# 自动探测：build 目录有 .config 且 CONFIG_CC_IS_CLANG=y 就用 clang/lld。
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

ifeq ($(shell grep -q '^CONFIG_CC_IS_CLANG=y' $(KDIR)/.config 2>/dev/null && echo yes),yes)
CC  := clang
LD  := ld.lld
else
CC  := gcc
LD  := ld
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CC) LD=$(LD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) CC=$(CC) LD=$(LD) clean
