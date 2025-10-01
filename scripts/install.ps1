# Binspector installer for Windows (PowerShell)
# Strategy:
#  - If a local release binary exists, install that.
#  - Else, if cargo exists, build from source and install the built artifact.
#  - Else, install Rust toolchain (rustup) using winget/choco/scoop or rustup-init.exe, then build and install.
#  - Installs to a user-writable bin dir (default: $Env:USERPROFILE\.cargo\bin if present; else $Env:LOCALAPPDATA\Binspector\bin). Override with -Dest.

[CmdletBinding()]
param(
  [string]$Dest,
  [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

function Log($msg) { if (-not $Quiet) { Write-Host "[install] $msg" } }
function Err($msg) { Write-Error "[install][error] $msg" }

function Test-Command {
  param([string]$Name)
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Ensure-Dir {
  param([string]$Path)
  if (-not (Test-Path $Path)) {
    New-Item -ItemType Directory -Path $Path | Out-Null
  }
}

function Default-Dest {
  if ($Dest) { return $Dest }
  $cargoBin = Join-Path $Env:USERPROFILE ".cargo\bin"
  if (Test-Path $cargoBin) { return $cargoBin }
  return (Join-Path $Env:LOCALAPPDATA "Binspector\bin")
}

function Ensure-Rust {
  if (Test-Command cargo) { return }
  Log "Cargo not found; attempting to install Rust (rustup)"
  if (Test-Command winget) {
    try {
      winget install -e --id Rustlang.Rustup -h --accept-source-agreements --accept-package-agreements
    } catch {}
  }
  if (-not (Test-Command cargo) -and (Test-Command choco)) {
    try { choco install -y rustup } catch {}
  }
  if (-not (Test-Command cargo) -and (Test-Command scoop)) {
    try { scoop install rustup } catch {}
  }
  if (-not (Test-Command cargo)) {
    # Fallback: download rustup-init.exe
    $tmp = New-Item -ItemType Directory -Path ([System.IO.Path]::Combine($env:TEMP, "binspector-install")) -Force
    $rustup = Join-Path $tmp.FullName "rustup-init.exe"
    $url = "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe"
    Log "Downloading rustup-init.exe"
    Invoke-WebRequest -Uri $url -OutFile $rustup
    & $rustup -y
  }
  # Ensure cargo is available in this session
  $cargoEnv = Join-Path $Env:USERPROFILE ".cargo\env"
  if (Test-Path $cargoEnv) { . $cargoEnv }
  if (-not (Test-Command cargo)) {
    Err "Cargo not found after attempted Rust install. Aborting."
    exit 1
  }
}

function Build-From-Source {
  Log "Building binspector (release)"
  & cargo build --release
}

function Add-To-UserPath {
  param([string]$Dir)
  $current = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not $current) { $current = '' }
  $parts = $current.Split(';') | Where-Object { $_ -and $_.Trim() -ne '' }
  if ($parts -notcontains $Dir) {
    $newPath = if ($current) { "$current;$Dir" } else { $Dir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    Log "Added to User PATH: $Dir (restart terminal to use)"
  }
}

function Main {
  $destDir = Default-Dest
  Log "Install destination: $destDir"
  Ensure-Dir $destDir

  $binSrc = Join-Path (Join-Path (Get-Location) "target\release") "binspector.exe"
  if (Test-Path $binSrc) {
    Log "Using existing build at $binSrc"
  } else {
    if (Test-Command cargo) {
      Build-From-Source
    } else {
      Ensure-Rust
      Build-From-Source
    }
    if (-not (Test-Path $binSrc)) {
      Err "Build artifact not found at $binSrc"
      exit 1
    }
  }

  $destExe = Join-Path $destDir "binspector.exe"
  Copy-Item -Force $binSrc $destExe
  Log "Installed binspector to $destExe"
  Add-To-UserPath -Dir $destDir
  Log "Done. Try: binspector --help"
}

Main

