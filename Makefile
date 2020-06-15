KDIR ?= /lib/modules/`uname -r`/build
IPTABLES_MODULES = /usr/lib/x86_64-linux-gnu/xtables
DEPMOD = /sbin/depmod -a
CFLAGS = -fPIC

#obj-m  := ebt_arpreply.o
obj-m  := ebt_pmtud.o

all: ebt_pmtud.ko libebt_pmtud.so

%.ko: %.c
	$(MAKE) -C $(KDIR) M=$$PWD $@

%.so: %.o
	$(CC) -shared -o $@ $<

install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install INSTALL_MOD_PATH=$(DESTDIR)
	$(DEPMOD)
	install -D *.so $(DESTDIR)$(IPTABLES_MODULES)/

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	rm -f *.ko *.o 
