# This Makefile is intended for developer convenience.  For the most part
# all the targets here simply wrap calls to the `cargo` tool.  Therefore,
# most targets must be marked 'PHONY' to prevent `make` getting in the way
#
#prog :=xnixperms

DESTDIR ?=
PREFIX ?= /usr/local
LIBEXECDIR ?= ${PREFIX}/libexec
LIBEXECPODMAN ?= ${LIBEXECDIR}/podman
SYSTEMDDIR ?= ${PREFIX}/lib/systemd/system

SELINUXOPT ?= $(shell test -x /usr/sbin/selinuxenabled && selinuxenabled && echo -Z)
# Get crate version by parsing the line that starts with version.
CRATE_VERSION ?= $(shell grep ^version Cargo.toml | awk '{print $$3}')
GIT_TAG ?= $(shell git describe --tags)

# Set this to any non-empty string to enable unoptimized
# build w/ debugging features.
debug ?=

# Set path to cargo executable
CARGO ?= cargo

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
build: build_netavark build_proxy_client

.PHONY: build_netavark
build_netavark: bin $(CARGO_TARGET_DIR)
	$(CARGO) build $(release)
	cp $(CARGO_TARGET_DIR)/$(profile)/netavark bin/netavark$(if $(debug),.debug,)

.PHONY: examples
examples: bin $(CARGO_TARGET_DIR)
	cargo build --examples $(release)

.PHONY: crate-publish
crate-publish:
	@if [ "v$(CRATE_VERSION)" != "$(GIT_TAG)" ]; then\
		echo "Git tag is not equivalent to the version set in Cargo.toml. Please checkout the correct tag";\
		exit 1;\
	fi
	@echo "It is expected that you have already done 'cargo login' before running this command. If not command may fail later"
	$(CARGO) publish --dry-run
	$(CARGO) publish

.PHONY: clean
clean:
	rm -rf bin
	if [ "$(CARGO_TARGET_DIR)" = "targets" ]; then rm -rf targets; fi
	$(MAKE) -C docs clean

.PHONY: client
client: bin $(CARGO_TARGET_DIR)
	$(CARGO) build --bin netavark-dhcp-proxy-client $(release)


.PHONY: docs
docs: ## build the docs on the host
	$(MAKE) -C docs

NV_UNIT_FILES = contrib/systemd/system/netavark-dhcp-proxy.service \
				contrib/systemd/system/netavark-firewalld-reload.service

%.service: %.service.in
	sed -e 's;@@NETAVARK@@;$(LIBEXECPODMAN)/netavark;g' $< >$@.tmp.$$ \
		&& mv -f $@.tmp.$$ $@

.PHONY: install
install: $(NV_UNIT_FILES)
	install ${SELINUXOPT} -D -m0755 bin/netavark $(DESTDIR)$(LIBEXECPODMAN)/netavark
	install ${SELINUXOPT} -D -m0755 bin/netavark-dhcp-proxy-client $(DESTDIR)$(LIBEXECPODMAN)/netavark-dhcp-proxy-client
	$(MAKE) -C docs install
	install ${SELINUXOPT} -m 755 -d ${DESTDIR}${SYSTEMDDIR}
	install ${SELINUXOPT} -m 644 contrib/systemd/system/netavark-dhcp-proxy.socket ${DESTDIR}${SYSTEMDDIR}/netavark-dhcp-proxy.socket
	install ${SELINUXOPT} -m 644 contrib/systemd/system/netavark-dhcp-proxy.service ${DESTDIR}${SYSTEMDDIR}/netavark-dhcp-proxy.service
	install ${SELINUXOPT} -m 644 contrib/systemd/system/netavark-firewalld-reload.service ${DESTDIR}${SYSTEMDDIR}/netavark-firewalld-reload.service

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(LIBEXECPODMAN)/netavark
	rm -f $(PREFIX)/share/man/man1/netavark*.1
	rm -f ${DESTDIR}${SYSTEMDDIR}/netavark-dhcp-proxy.service
	rm -f ${DESTDIR}${SYSTEMDDIR}/netavark-dhcp-proxy.socket

.PHONY: test
test: unit integration

# Used by CI to compile the unit tests but not run them
.PHONY: build_unit
build_unit: $(CARGO_TARGET_DIR)
	$(CARGO) test --no-run

.PHONY: unit
unit: $(CARGO_TARGET_DIR)
	$(CARGO) test

.PHONY: integration
integration: $(CARGO_TARGET_DIR) examples
	# needs to be run as root or with podman unshare --rootless-netns
	bats test/
	bats test-dhcp/

.PHONY: validate
validate: $(CARGO_TARGET_DIR)
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy -p netavark -- -D warnings
	$(MAKE) docs

.PHONY: vendor-tarball
vendor-tarball: build install.cargo-vendor-filterer
	VERSION=$(shell bin/netavark --version | cut -f2 -d" ") && \
	$(CARGO) vendor-filterer --format=tar.gz --prefix vendor/ && \
	mv vendor.tar.gz netavark-v$$VERSION-vendor.tar.gz && \
	gzip -c bin/netavark > netavark.gz && \
	sha256sum netavark.gz netavark-v$$VERSION-vendor.tar.gz > sha256sum

.PHONY: install.cargo-vendor-filterer
install.cargo-vendor-filterer:
	$(CARGO) install cargo-vendor-filterer

.PHONY: mock-rpm
mock-rpm:
	rpkg local

.PHONY: help
help:
	@echo "usage: make $(prog) [debug=1]"

.PHONY: build_proxy_client
build_proxy_client: bin $(CARGO_TARGET_DIR)
	$(CARGO) build --bin netavark-dhcp-proxy-client $(release)
	cp $(CARGO_TARGET_DIR)/$(profile)/netavark-dhcp-proxy-client bin/netavark-dhcp-proxy-client$(if $(debug),.debug,)
