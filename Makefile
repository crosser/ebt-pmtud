KDIR ?= /lib/modules/`uname -r`/build

#obj-m  := ebt_arpreply.o
obj-m  := ebt_pmtud.o

default:
	$(MAKE) -C $(KDIR) M=$$PWD

.DEFAULT:
	$(MAKE) -C $(KDIR) M=$$PWD $@
