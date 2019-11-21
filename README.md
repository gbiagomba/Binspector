# Binspector
This script inspects an executable binary for close to two-hundred (200) banned C functions. Then, it performs fuzzing of the binary.

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
https://docs.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10)?redirectedfrom=MSDN
https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions
https://github.com/microsoft/ChakraCore/blob/master/lib/Common/Banned.h
https://security.web.cern.ch/security/recommendations/en/codetools/c.shtml
