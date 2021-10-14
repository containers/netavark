# TODO: Make this more configurable
#prog :=xnixperms

debug ?=

ifdef debug
$(info debug is $(debug))
  release :=
  target :=debug
  extension :=debug
else
  release :=--release
  target :=release
  extension :=
endif

build:
	cargo build $(release) --target-dir bin
	cp bin/$(target)/netavark bin/netavark

clean:
	rm -rf bin
	$(MAKE) -C docs clean

.PHONY: docs
docs: ## build the docs on the host
	$(MAKE) -C docs

.PHONY: install
install:
	install -D -m0755 bin/buildah $(DESTDIR)/$(BINDIR)/netavark
	$(MAKE) -C docs install

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)/$(BINDIR)/netavark
	rm -f $(PREFIX)/share/man/man1/netavark*.1

test:
	cargo test

validate:
	cargo clippy -p netavark -- -D warnings
all: build docs

help:
	@echo "usage: make $(prog) [debug=1]"
