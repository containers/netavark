# TODO: Make this more configurable
#prog :=xnixperms

DESTDIR ?=
PREFIX ?= /usr/local
LIBEXECDIR ?= ${PREFIX}/libexec
LIBEXECPODMAN ?= ${LIBEXECDIR}/podman

SELINUXOPT ?= $(shell test -x /usr/sbin/selinuxenabled && selinuxenabled && echo -Z)

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
install: docs build
	install ${SELINUXOPT} -D -m0755 bin/netavark $(DESTDIR)/$(LIBEXECPODMAN)/netavark
	$(MAKE) -C install

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)/$(LIBEXECPODMAN)/netavark
	rm -f $(PREFIX)/share/man/man1/netavark*.1

test:
	cargo test

validate:
	cargo fmt --all -- --check
	cargo clippy -p netavark -- -D warnings

all: build docs

help:
	@echo "usage: make $(prog) [debug=1]"
