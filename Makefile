SHELL := /bin/bash

APP := binspector
TARGET ?=
FEATURES ?=
HARD ?= 1500
ITERATIONS ?= 20000
SEED ?= 0
SOFT ?= 1000

.PHONY: all build release run test test-all fmt fmt-check lint loc-check check clean \
        normalize-banned-list docker help fuzz-build fuzz-diff fuzz-corpus fuzz-afl fuzz-hfuzz

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
	@echo ""
	@echo "Fuzzing:"
	@echo "  fuzz-build            build the plain harnesses (no engine needed)"
	@echo "  fuzz-diff BIN=path    differential fuzz Binspector's parsers against a sample"
	@echo "  fuzz-corpus BIN=path  build a seed corpus from a sample"
	@echo "  fuzz-afl TARGET=name  build an AFL-instrumented target (needs cargo-afl)"
	@echo "  fuzz-hfuzz TARGET=name  build a honggfuzz target (needs cargo-hfuzz)"
	@echo "  clean                 remove build artifacts"
	@echo ""
	@echo "Features:"
	@echo "  sqlite   binary --format sqlite output"
	@echo "  carve    embedded signature carving via binwalk"
	@echo "Both off by default. Use FEATURES=carve or cargo --all-features."

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

# The harnesses build without any engine installed, which is what CI checks.
fuzz-build:
	cd fuzz && cargo build --release

fuzz-diff:
	@if [ -z "$(BIN)" ]; then echo "Usage: make fuzz-diff BIN=path/to/sample"; exit 1; fi
	cargo run --release -- fuzz --differential "$(BIN)" --iterations $(ITERATIONS) \
		--seed $(SEED) --fail-on-finding

fuzz-corpus:
	@if [ -z "$(BIN)" ]; then echo "Usage: make fuzz-corpus BIN=path/to/sample"; exit 1; fi
	cargo run --release -- fuzz --corpus-from "$(BIN)"

fuzz-afl:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make fuzz-afl TARGET=fuzz_pe"; exit 1; fi
	cd fuzz && cargo afl build --features afl-target --release --bin $(TARGET)

fuzz-hfuzz:
	@if [ -z "$(TARGET)" ]; then echo "Usage: make fuzz-hfuzz TARGET=fuzz_pe"; exit 1; fi
	cd fuzz && cargo hfuzz build --features hfuzz-target --bin $(TARGET)

clean:
	cargo clean
	cd fuzz && cargo clean

normalize-banned-list:
	@python3 scripts/normalize_banned_list.py
