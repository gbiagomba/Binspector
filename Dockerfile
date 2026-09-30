# Multi-stage build for binspector.
#
# All optional features (sqlite, carve, repl) are on by default since 4.4.0.
# FEATURES adds extra cargo features; CARGO_FLAGS passes raw flags, which is how a
# minimal image is built:
#   docker build --build-arg CARGO_FLAGS=--no-default-features -t binspector .
FROM rust:1.90-slim AS build
ARG FEATURES=""
ARG CARGO_FLAGS=""
WORKDIR /app

# Cache dependency compilation against the manifests alone.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
 && echo 'fn main() {}' > src/main.rs \
 && echo '' > src/lib.rs \
 && cargo build --release $CARGO_FLAGS $(test -n "$FEATURES" && echo "--features $FEATURES") \
 && rm -rf src

# Build the real application. The banned list is included via include_str!, so rsc/
# must be present at compile time.
COPY src ./src
COPY rsc ./rsc
RUN touch src/main.rs src/lib.rs \
 && cargo build --release $CARGO_FLAGS $(test -n "$FEATURES" && echo "--features $FEATURES")

FROM debian:bookworm-slim
RUN useradd -ms /bin/bash app
WORKDIR /home/app
COPY --from=build /app/target/release/binspector /usr/local/bin/binspector
# Shipped for reference and for use with --banned-list.
COPY rsc/sdl_banned_funct.list /etc/binspector/sdl_banned_funct.list

# Scanning needs no write access: archives are unpacked in memory and nothing is
# written to disk unless -o is given.
USER app
ENTRYPOINT ["/usr/local/bin/binspector"]
CMD ["--help"]
