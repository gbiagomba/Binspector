#!/usr/bin/env bash
set -euo pipefail

# Binspector installer for Unix-like systems (Linux, macOS, *BSD)
# Strategy:
#  - If a local release binary exists, install that.
#  - Else, if cargo exists, build from source and install the built artifact.
#  - Else, install Rust toolchain (rustup) using the best available method per distro, then build and install.
#  - Installs to a writeable bin dir (default: /usr/local/bin when root; else $HOME/.local/bin). Override with --dest DIR.

APP_NAME="binspector"
DEST=""
QUIET=0

log() { if [[ "$QUIET" -eq 0 ]]; then echo "[install] $*"; fi; }
err() { echo "[install][error] $*" >&2; }

usage() {
  cat <<EOF
Usage: $0 [--dest DIR] [--quiet]

Installs ${APP_NAME} by using an existing build, or building from source.

Options:
  --dest DIR   Install directory (default: /usr/local/bin if root; else ~/.local/bin)
  --quiet      Reduce output
  -h, --help   Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dest)
      DEST=${2:-}
      shift 2
      ;;
    --quiet)
      QUIET=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *) err "Unknown argument: $1"; usage; exit 2 ;;
  esac
done

require_cmd() { command -v "$1" >/dev/null 2>&1; }

is_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

default_dest() {
  if [[ -n "$DEST" ]]; then
    printf "%s" "$DEST"
    return
  fi
  if is_root; then
    printf "/usr/local/bin"
  else
    printf "%s/.local/bin" "$HOME"
  fi
}

ensure_dir_writable() {
  local d="$1"
  if [[ -d "$d" && -w "$d" ]]; then return 0; fi
  if [[ ! -d "$d" ]]; then
    if mkdir -p "$d" 2>/dev/null; then return 0; fi
  fi
  # try sudo if available
  if require_cmd sudo; then
    log "Using sudo to create or write to $d"
    sudo mkdir -p "$d"
    sudo chown "$(id -u)":"$(id -g)" "$d" 2>/dev/null || true
  else
    err "Directory $d is not writable and sudo is not available. Set --dest to a writeable dir."
    return 1
  fi
}

copy_with_perm() {
  local src="$1" destdir="$2" name="$3"
  chmod +x "$src" || true
  if [[ -w "$destdir" ]]; then
    cp "$src" "$destdir/$name"
  elif require_cmd sudo; then
    sudo cp "$src" "$destdir/$name"
  else
    err "Cannot write to $destdir and sudo not available"
    return 1
  fi
}

detect_os() {
  local u
  u=$(uname -s 2>/dev/null || echo unknown)
  case "$u" in
    Linux) echo linux ;;
    Darwin) echo macos ;;
    FreeBSD|OpenBSD|NetBSD|DragonFly) echo bsd ;;
    *) echo other ;;
  esac
}

install_rust_linux() {
  # Try native pkg managers for curl/build tools; then rustup
  if require_cmd apt-get; then
    log "Installing prerequisites via apt-get"
    sudo apt-get update -y
    sudo apt-get install -y curl ca-certificates build-essential pkg-config
  elif require_cmd dnf; then
    log "Installing prerequisites via dnf"
    sudo dnf install -y curl ca-certificates gcc make pkgconf-pkg-config
  elif require_cmd yum; then
    log "Installing prerequisites via yum"
    sudo yum install -y curl ca-certificates gcc make pkgconfig
  elif require_cmd pacman; then
    log "Installing prerequisites via pacman"
    sudo pacman -Sy --noconfirm curl ca-certificates base-devel pkgconf
  elif require_cmd zypper; then
    log "Installing prerequisites via zypper"
    sudo zypper --non-interactive install curl ca-certificates gcc make pkg-config
  elif require_cmd apk; then
    log "Installing prerequisites via apk"
    sudo apk add --no-cache curl ca-certificates build-base pkgconf
  else
    log "Unknown Linux distro; proceeding to rustup install if curl works"
  fi
  if ! require_cmd curl; then
    err "curl is required to bootstrap rustup; please install curl and rerun."
    return 1
  fi
  log "Installing Rust via rustup"
  curl https://sh.rustup.rs -sSf | sh -s -- -y
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
}

install_rust_macos() {
  if require_cmd brew; then
    log "Installing Rust via Homebrew (rustup)"
    # Prefer rustup if available; fallback to rust
    if brew info rustup-init >/dev/null 2>&1; then
      brew install rustup-init
      rustup-init -y
    else
      brew install rust
    fi
  else
    if ! require_cmd curl; then
      err "curl is required to bootstrap rustup; install Homebrew (https://brew.sh) or curl, then rerun."
      return 1
    fi
    log "Installing Rust via rustup"
    curl https://sh.rustup.rs -sSf | sh -s -- -y
  fi
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
}

ensure_rust() {
  if require_cmd cargo; then return 0; fi
  local os
  os=$(detect_os)
  case "$os" in
    linux) install_rust_linux ;;
    macos|bsd) install_rust_macos ;;
    *) err "Unsupported OS for automated rust install. Please install Rust manually from https://rustup.rs"; return 1 ;;
  esac
  if ! require_cmd cargo; then
    err "Cargo not found after attempted install. Aborting."
    return 1
  fi
}

build_from_source() {
  log "Building ${APP_NAME} (release)"
  cargo build --release
}

main() {
  local destdir bin_src
  destdir=$(default_dest)
  log "Install destination: $destdir"
  ensure_dir_writable "$destdir"

  if [[ -f "target/release/${APP_NAME}" ]]; then
    bin_src="target/release/${APP_NAME}"
    log "Using existing build at $bin_src"
  else
    if require_cmd cargo; then
      build_from_source
    else
      log "Cargo not found; bootstrapping Rust toolchain"
      ensure_rust
      build_from_source
    fi
    bin_src="target/release/${APP_NAME}"
  fi

  if [[ ! -f "$bin_src" ]]; then
    err "Build artifact not found at $bin_src"
    exit 1
  fi

  copy_with_perm "$bin_src" "$destdir" "$APP_NAME"
  log "Installed ${APP_NAME} to ${destdir}/${APP_NAME}"
  if [[ ":$PATH:" != *":$destdir:"* ]]; then
    log "Note: $destdir is not on your PATH. Consider adding:\n  export PATH=\"$destdir:\$PATH\""
  fi
  log "Done. Try: ${APP_NAME} --help"
}

main "$@"

