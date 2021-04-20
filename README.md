# Binspector
This script inspects an executable binary for close to two-hundred (200) banned C functions. Then, it performs fuzzing of the binary.

## Install
```
cd /opt/
git clone https://github.com/gbiagomba/Binspector
cd Binspector
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
1. https://docs.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10)?redirectedfrom=MSDN
2. https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions
3. https://github.com/microsoft/ChakraCore/blob/master/lib/Common/Banned.h
4. https://security.web.cern.ch/security/recommendations/en/codetools/c.shtml
