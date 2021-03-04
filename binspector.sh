#!/usr/bin/env bash
# Author: Gilles Biagomba
# Program: Binspector
# Description: This script is designed to inspect binaries for banned C functions.\n
#              Additionally, it performs fuzzing of the binary.\n

# for debugging purposes
# set -eux
trap "echo Booh!" SIGINT SIGTERM

# Checking if the user is root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Declaring variables
current_time=$(date "+%Y.%m.%d-%H.%M.%S")
pth=$PWD
wrkpth="$PWD/Binspector"
wrktmp=$(mktemp -d)
bin=$1

# Setting Envrionment
mkdir -p  $wrkpth/PEFrame/ $wrkpth/Zzuf/ $wrkpth/Valgrind/ $wrkpth/Binwalk/ $wrkpth/cve-bin-tool/

# Moving back to original workspace & loading logo
cd $pth
echo "
 /&&      /&&&&&& /&&   /&&  /&&&&&&  /&&&&&&&  /&&&&&&&&  /&&&&&&  /&&&&&&&& /&&&&&&  /&&&&&&& 
| &&     |_  &&_/| &&& | && /&&__  &&| &&__  &&| &&_____/ /&&__  &&|__  &&__//&&__  &&| &&__  &&
| &&&&&&&  | &&  | &&&&| &&| &&  \__/| &&  \ &&| &&      | &&  \__/   | &&  | &&  \ &&| &&  \ &&
| &&__  && | &&  | && && &&|  &&&&&& | &&&&&&&/| &&&&&   | &&         | &&  | &&  | &&| &&&&&&&/
| &&  \ && | &&  | &&  &&&& \____  &&| &&____/ | &&__/   | &&         | &&  | &&  | &&| &&__  &&
| &&  | && | &&  | &&\  &&& /&&  \ &&| &&      | &&      | &&    &&   | &&  | &&  | &&| &&  \ &&
| &&&&&&&//&&&&&&| && \  &&|  &&&&&&/| &&      | &&&&&&&&|  &&&&&&/   | &&  |  &&&&&&/| &&  | &&
|_______/|______/|__/  \__/ \______/ |__/      |________/ \______/    |__/   \______/ |__/  |__/
                                                                                                                                                        
"
echo "Truth is confirmed by inspection and delay; falsehood by haste and uncertainly - Tacitus"
echo

# Requesting target file name or checking the target file exists & requesting the project name
if [ -z $bin ]; then
    echo "What is the name of the targets file? The file with all the IP addresses or sites"
    read bin
    echo
elif [ ! -e $bin ]; then
    echo "File not found! Try again!"
    exit
fi

echo "What is the name of the project?"
read prj_name
echo

# Checking for banned strings
echo "--------------------------------------------------"
echo "Checking for banned strings"
echo "--------------------------------------------------"
peframe $bin | tee $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.txt 2> /dev/null
echo | tee -a $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.txt
echo | tee -a $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.txt
echo "--------------------------------------------------------------------------------" | tee -a $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.txt
echo "Strings" | tee -a $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.txt
echo "--------------------------------------------------------------------------------" | tee -a $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.txt
peframe -s $bin | tee -a $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.txt 2> /dev/null
peframe -j $bin | tee $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.json 2> /dev/null

for str in $(cat /opt/Binspector/sdl_banned_funct.list); do
    if [ "`cat $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.txt | grep -o $str`" == "$str" ]; then
        echo "--------------------------------------------------" | tee -a $wrkpth/PEFrame/$prj_name-sdl_banned_funct-$current_time.txt
        echo "Checking for $str" | tee -a $wrkpth/PEFrame/$prj_name-sdl_banned_funct-$current_time.txt
        echo "--------------------------------------------------" | tee -a $wrkpth/PEFrame/$prj_name-sdl_banned_funct-$current_time.txt
        cat $wrkpth/PEFrame/$prj_name-peframe_output-$current_time.txt | grep $str | tee -a $wrkpth/PEFrame/$prj_name-sdl_banned_funct-$current_time.txt
        echo | tee -a $wrkpth/PEFrame/$prj_name-sdl_banned_funct-$current_time.txt
        # echo | tee -a $wrkpth/PEFrame/$prj_name-sdl_banned_funct-$current_time.txt
    fi
done

# Troubleshoot if statement below
if [ -z $wrkpth/PEFrame/$prj_name-sdl_banned_funct-$current_time.txt ]; then
    echo | tee -a $wrkpth/PEFrame/$prj_name-sdl_banned_funct-$current_time.txt
    echo "For more information on why you shouldn't use the aforementioned functions, see links below:
    https://security.web.cern.ch/security/recommendations/en/codetools/c.shtml
    https://github.com/intel/safestringlib/wiki/SDL-List-of-Banned-Functions
    https://docs.microsoft.com/en-us/previous-versions/bb288454(v=msdn.10)?redirectedfrom=MSDN
    " | tee -a $wrkpth/PEFrame/$prj_name-sdl_banned_funct-$current_time.txt
fi
echo 

# Placeholder
echo "--------------------------------------------------"
echo "Running binwalk"
echo "--------------------------------------------------"
cd $wrkpth/Binwalk/
binwalk -e $bin | tee $wrkpth/Binwalk/$prj_name-binwalk_output-$current_time.txt 2> /dev/null
cd $pth
echo 

# Placeholder
echo "--------------------------------------------------"
echo "Running cve-bin-tool"
cd $wrkpth/cve-bin-tool/
cve-bin-tool -i $bin -o $wrkpth/cve-bin-tool/$prj_name-cve-bin-tool_output-$current_time.txt -c 4 2> /dev/null
echo 

# Fuzzing executable binary
echo "--------------------------------------------------"
echo "Fuzzing executable binary"
echo "--------------------------------------------------"
# Command will go here
echo
