# TODO: Make this more configurable
#prog :=xnixperms

debug ?=

$(info debug is $(debug))

ifdef debug
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

all: build

help:
	@echo "usage: make $(prog) [debug=1]"
