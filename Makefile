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

test:
	cargo test

validate:
	cargo clippy -p netavark -- -D warnings
all: build

help:
	@echo "usage: make $(prog) [debug=1]"
