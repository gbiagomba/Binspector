# Multi-stage build for binspector
FROM rust:1.81 as build
WORKDIR /app

# Cache dependency compilation
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo "fn main(){}" > src/main.rs
RUN cargo build --release || true

# Build the real app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -ms /bin/bash app
WORKDIR /home/app
COPY --from=build /app/target/release/binspector /usr/local/bin/binspector
COPY sdl_banned_funct.list /etc/binspector/sdl_banned_funct.list
USER app
ENTRYPOINT ["/usr/local/bin/binspector"]
CMD ["--help"]
