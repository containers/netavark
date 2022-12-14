PREFIX ?= /usr/local
DATADIR ?= ${PREFIX}/share
MANDIR ?= $(DATADIR)/man
MANDOWN ?= mandown

docs: $(patsubst %.md,%,$(wildcard *.1.md))

%.1: %.1.md
	$(MANDOWN) $< > $@

.PHONY: .install.mandown
.install.mandown:
	cargo install mandown

.PHONY: install
install:
	install -d ${DESTDIR}/${MANDIR}/man1
	install -m 0644 *.1 ${DESTDIR}/${MANDIR}/man1

.PHONY: clean
clean:
	$(RM) *.1
