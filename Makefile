# This Makefile is intended for developer convenience.  For the most part
# all the targets here simply wrap calls to the `cargo` tool.  Therefore,
# most targets must be marked 'PHONY' to prevent `make` getting in the way
#
#prog :=xnixperms

DESTDIR ?=
PREFIX ?= /usr/local
LIBEXECDIR ?= ${PREFIX}/libexec
LIBEXECPODMAN ?= ${LIBEXECDIR}/podman

SELINUXOPT ?= $(shell test -x /usr/sbin/selinuxenabled && selinuxenabled && echo -Z)

# Set this to any non-empty string to enable unoptimized
# build w/ debugging features.
debug ?=

# All complication artifacts, including dependencies and intermediates
# will be stored here, for all architectures.  Use a non-default name
# since the (default) 'target' is used/referenced ambiguously in many
# places in the tool-chain (including 'make' itself).
CARGO_TARGET_DIR ?= targets
export CARGO_TARGET_DIR  # 'cargo' is sensitive to this env. var. value.

ifdef debug
$(info debug is $(debug))
  # These affect both $(CARGO_TARGET_DIR) layout and contents
  # Ref: https://doc.rust-lang.org/cargo/guide/build-cache.html
  release :=
  profile :=debug
else
  release :=--release
  profile :=release
endif

.PHONY: all
all: build

bin:
	mkdir -p $@

$(CARGO_TARGET_DIR):
	mkdir -p $@

.PHONY: build
build: bin $(CARGO_TARGET_DIR)
	cargo build $(release)
	cp $(CARGO_TARGET_DIR)/$(profile)/netavark bin/netavark$(if $(debug),.debug,)

.PHONY: clean
clean:
	rm -rf bin
	if [[ "$(CARGO_TARGET_DIR)" == "targets" ]]; then rm -rf targets; fi
	$(MAKE) -C docs clean

.PHONY: docs
docs: ## build the docs on the host
	$(MAKE) -C docs

.PHONY: install
install:
	install ${SELINUXOPT} -D -m0755 bin/netavark $(DESTDIR)/$(LIBEXECPODMAN)/netavark
	$(MAKE) -C docs install

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)/$(LIBEXECPODMAN)/netavark
	rm -f $(PREFIX)/share/man/man1/netavark*.1

.PHONY: test
test: unit integration

# Used by CI to compile the unit tests but not run them
.PHONY: build_unit
build_unit: $(CARGO_TARGET_DIR)
	cargo test --no-run

# Test build cross-architecture
.PHONY: build_cross
build_cross: $(CARGO_TARGET_DIR)
	cargo install cross
	rustup target add aarch64-unknown-linux-gnu
	rustup target add arm-unknown-linux-gnueabi
	cross build --target aarch64-unknown-linux-gnu
	cross build --target arm-unknown-linux-gnueabi

.PHONY: unit
unit: $(CARGO_TARGET_DIR)
	cargo test

.PHONY: integration
integration: $(CARGO_TARGET_DIR)
	# needs to be run as root or with podman unshare --rootless-netns
	bats test/

.PHONY: validate
validate: $(CARGO_TARGET_DIR)
	cargo fmt --all -- --check
	cargo clippy -p netavark -- -D warnings

.PHONY: vendor
vendor: ## vendor everything into vendor/
	cargo vendor
	$(MAKE) vendor-rm-windows ## remove windows library if possible

.PHONY: vendor-rm-windows
vendor-rm-windows:
	if [ -d "vendor/winapi" ]; then \
		rm -fr vendor/winapi*gnu*/lib/*.a; \
	fi

.PHONY: mock-rpm
mock-rpm:
	rpkg local

.PHONY: help
help:
	@echo "usage: make $(prog) [debug=1]"
