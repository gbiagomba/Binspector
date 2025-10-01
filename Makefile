SHELL := /bin/bash

APP := binspector
TARGET ?=
FEATURES ?=

.PHONY: all build release run test fmt lint clean

all: build

build:
	cargo build $(if $(TARGET),--target $(TARGET),) $(if $(FEATURES),--features $(FEATURES),)

release:
	cargo build --release $(if $(TARGET),--target $(TARGET),) $(if $(FEATURES),--features $(FEATURES),)

run:
	@if [ -z "$(BIN)" ]; then echo "Usage: make run BIN=path/to/binary"; exit 1; fi
	cargo run -- $(BIN)

test:
	cargo test --all

fmt:
	cargo fmt --all || true

lint:
	cargo clippy --all-targets --all-features -- -D warnings || true

clean:
	cargo clean
