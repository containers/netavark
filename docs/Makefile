PREFIX ?= /usr/local
DATADIR ?= ${PREFIX}/share
MANDIR ?= $(DATADIR)/man
MANDOWN ?= $(shell command -v mandown)

docs: $(patsubst %.md,%,$(wildcard *.md))

%.1: %.1.md
### sed is used to filter http/s links as well as relative links
### replaces "\" at the end of a line with two spaces
### this ensures that manpages are renderd correctly

	@sed -e 's/\((buildah[^)]*\.md\(#.*\)\?)\)//g' \
	 -e 's/\[\(buildah[^]]*\)\]/\1/g' \
	 -e 's/\[\([^]]*\)](http[^)]\+)/\1/g' \
	 -e 's;<\(/\)\?\(a\|a\s\+[^>]*\|sup\)>;;g' \
	 -e 's/\\$$/  /g' $<  | \
	$(MANDOWN) /dev/stdin > $@

.PHONY: install
install:
	install -d ${DESTDIR}/${MANDIR}/man1
	install -m 0644 *.1 ${DESTDIR}/${MANDIR}/man1

.PHONY: clean
clean:
	$(RM) *.1
