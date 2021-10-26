PREFIX ?= /usr/local
DATADIR ?= ${PREFIX}/share
MANDIR ?= $(DATADIR)/man
MANDOWN ?= $(shell command -v mandown)

docs: $(patsubst %.md,%,$(wildcard *.md))

%.1: %.1.md
	$(MANDOWN) $< > $@

.PHONY: install
install:
	install -d ${DESTDIR}/${MANDIR}/man1
	install -m 0644 *.1 ${DESTDIR}/${MANDIR}/man1

.PHONY: clean
clean:
	$(RM) *.1
