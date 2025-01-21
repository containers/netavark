PREFIX ?= /usr/local
DATADIR ?= ${PREFIX}/share
MANDIR ?= $(DATADIR)/man
GO ?= go
GOMD2MAN ?= go-md2man

docs: $(patsubst %.md,%,$(wildcard *.[0-9].md))

%.1: %.1.md
	$(GOMD2MAN) -in $^ -out $@

%.7: %.7.md
	$(GOMD2MAN) -in $^ -out $@

.PHONY: .install.md2man
.install.md2man:
	$(GO) install github.com/cpuguy83/go-md2man/v2@latest

.PHONY: install
install:
	install -d ${DESTDIR}/${MANDIR}/man1
	install -m 0644 *.1 ${DESTDIR}/${MANDIR}/man1
	install -d ${DESTDIR}/${MANDIR}/man7
	install -m 0644 *.7 ${DESTDIR}/${MANDIR}/man7

.PHONY: clean
clean:
	$(RM) *.1
