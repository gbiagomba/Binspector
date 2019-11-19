# BinInspector
This script is designed to inspect binaries for banned C functions. Additionally, it performs fuzzing of the binary.

## Install
```
cd /opt/
git pull https://github.com/gbiagomba/Sherlock
cd Sherlock
./install.sh
```

## Usage
```
binspector binary.exe
```
Do not worry all the prompts will be asked as the tool runs

## TODO
- [ ] Binary fuzzing [ ]
- [ ] Generating crashed binaries [ ]
- [ ] Inspecting crashed binary for what caused the crash [ ]
- [ ] Checking hashes against VT [ ]

## References
https://security.web.cern.ch/security/recommendations/en/codetools/c.shtml
https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions
