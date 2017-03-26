include ../Makefile.opt

SRCDIR = encoder security 

all: 
	@for d in $(SRCDIR) ; do $(MAKE) -C $$d all; done

install:
	@for d in $(SRCDIR) ; do $(MAKE) -C $$d install; done

uninstall:
	@for d in $(SRCDIR) ; do $(MAKE) -C $$d uninstall; done

clean:
	@for d in $(SRCDIR) ; do $(MAKE) -C $$d clean; done

depend:
	@for d in $(SRCDIR) ; do $(MAKE) -C $$d depend; done

test: 
	@for d in $(SRCDIR) ; do $(MAKE) -C $$d test; done



