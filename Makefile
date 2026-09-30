SHELL := /bin/bash

APP := binspector
TARGET ?=
FEATURES ?=
HARD ?= 1500
SOFT ?= 1000

.PHONY: all build release run test test-all fmt fmt-check lint loc-check check clean \
        normalize-banned-list docker help

all: build

help:
	@echo "Targets:"
	@echo "  build                 debug build"
	@echo "  release               optimized build"
	@echo "  run BIN=path          scan a file"
	@echo "  test                  unit and integration tests"
	@echo "  test-all              tests with every feature enabled (builds SQLite)"
	@echo "  lint                  clippy with warnings denied"
	@echo "  fmt / fmt-check       format, or verify formatting"
	@echo "  loc-check             enforce the per-file line budget"
	@echo "  check                 fmt-check + lint + loc-check + test"
	@echo "  docker                build the container image"
	@echo "  clean                 remove build artifacts"
	@echo ""
	@echo "Features: sqlite (binary --format sqlite output; off by default)"

build:
	cargo build $(if $(TARGET),--target $(TARGET),) $(if $(FEATURES),--features $(FEATURES),)

release:
	cargo build --release $(if $(TARGET),--target $(TARGET),) $(if $(FEATURES),--features $(FEATURES),)

run:
	@if [ -z "$(BIN)" ]; then echo "Usage: make run BIN=path/to/binary"; exit 1; fi
	cargo run -- $(BIN)

test:
	cargo test --all

test-all:
	cargo test --all --all-features

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets -- -D warnings

# No .rs file may exceed HARD lines; anything over SOFT is reported so it gets
# split before more is added to it.
loc-check:
	@HARD=$(HARD) SOFT=$(SOFT) ./scripts/loc_check.sh

check: fmt-check lint loc-check test

docker:
	docker build -t $(APP):latest .

clean:
	cargo clean

normalize-banned-list:
	@python3 scripts/normalize_banned_list.py
