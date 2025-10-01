**Overview**
- Scripts in this directory help install the `binspector` CLI across Unix/macOS and Windows. They prioritize using an existing local build, then fall back to building from source and optionally bootstrapping Rust.

**Installers**
- `install.sh`: Unix/macOS installer. Detects OS, builds with `cargo` if needed, and installs the binary.
- `install.ps1`: Windows (PowerShell) installer. Builds with `cargo` if needed and updates the User `PATH`.

**Usage**
- Unix/macOS: run `./scripts/install.sh` from the repo root.
- Windows: run `powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1` from the repo root.

**Options**
- `install.sh`:
  - `--dest DIR`: Install directory. Defaults to `/usr/local/bin` when root; otherwise `$HOME/.local/bin`.
  - `--quiet`: Reduce output.
- `install.ps1`:
  - `-Dest <DIR>`: Install directory. Defaults to `$Env:USERPROFILE\.cargo\bin` if it exists; otherwise `$Env:LOCALAPPDATA\Binspector\bin`.
  - `-Quiet`: Reduce output.

**Behavior**
- Uses an existing build if present at `target/release/binspector` (Unix) or `target\release\binspector.exe` (Windows).
- If `cargo` is available, builds via `cargo build --release`.
- If `cargo` is not available, attempts to install Rust (rustup):
  - Linux: uses `apt-get`, `dnf`, `yum`, `pacman`, `zypper`, or `apk` to prepare prerequisites, then `rustup`.
  - macOS/*BSD: via Homebrew (`rustup-init` or `rust`) if available; else direct `rustup`.
  - Windows: tries `winget`, `choco`, or `scoop`; else downloads `rustup-init.exe`.
- Installs the built binary to the destination directory.
- PATH handling:
  - Unix/macOS: prints a hint if the install directory is not on `PATH`.
  - Windows: appends the destination to the User `PATH`.

**Prerequisites**
- Network access to fetch Rust via `rustup` if `cargo` is missing.
- Permissions to write to the chosen install directory (use `--dest`/`-Dest` for user-writable locations).

**Troubleshooting**
- If build fails, ensure the Rust toolchain is installed and up to date: `rustup update`.
- On Linux, install basic build tools if missing (e.g., `build-essential` on Debian/Ubuntu or `base-devel` on Arch).
- On macOS, ensure Command Line Tools are installed: `xcode-select --install`.
- If the installed binary isn’t found, ensure the install directory is on your `PATH`.

