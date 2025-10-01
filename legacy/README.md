Purpose

- Legacy v1 Bash implementation and installers kept for historical reference. The current Binspector is a Rust CLI; these scripts are not used by the Rust build or runtime.

Contents

- `binspector.sh`: Original shell-based scanner that invoked external tools (e.g., peframe, binwalk, VirusTotal/MetaDefender CLIs, cve-bin-tool, valgrind, zzuf).
- `install.sh`, `mac_install.sh`: Legacy install helpers for the shell version.

Notes

- The shell script expected a `sdl_banned_funct.list` at an install path (e.g., `/opt/Binspector/sdl_banned_funct.list`). The Rust CLI now embeds `rsc/sdl_banned_funct.list` and no longer depends on these scripts.
