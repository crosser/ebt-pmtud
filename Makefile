KDIR ?= /lib/modules/`uname -r`/build

#obj-m  := ebt_arpreply.o
obj-m  := ebt_pmtud.o

all: ebt_pmtud.ko libebt_pmtud.so

%.ko:
	$(MAKE) -C $(KDIR) M=$$PWD $@

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	rm -f *.ko *.o 
