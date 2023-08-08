PREFIX ?= /usr/local
DATADIR ?= ${PREFIX}/share
MANDIR ?= $(DATADIR)/man
GO ?= go
GOMD2MAN ?= go-md2man

docs: $(patsubst %.md,%,$(wildcard *.1.md))

%.1: %.1.md
	$(GOMD2MAN) -in $^ -out $@

.PHONY: .install.md2man
.install.md2man:
	$(GO) install github.com/cpuguy83/go-md2man/v2@latest

.PHONY: install
install:
	install -d ${DESTDIR}/${MANDIR}/man1
	install -m 0644 *.1 ${DESTDIR}/${MANDIR}/man1

.PHONY: clean
clean:
	$(RM) *.1
