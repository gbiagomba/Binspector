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
diskMax=90
diskSize=$(df -kh $PWD | grep -iv filesystem | grep -o '[1-9]\+'%)
pth=$PWD
wrkpth="$PWD/Binspector"
wrktmp=$(mktemp -d)
bin=$1

# Checking system resources (HDD space)
if [[ "$diskSize" -ge "$diskMax" ]]; then
	clear
	echo 
	echo "You are using $diskSize% and I am concerned you might run out of space"
	echo "Remove some files and try again, you will thank me later, trust me :)"
	exit
fi

# Setting Envrionment
for i in PEFrame Zzuf Valgrind Binwalk cve-bin-tool; do
    if [ ! -e $wrkpth/$i ]; then
        mkdir -p $wrkpth/$i
    fi
done

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

{
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
binwalk -e $pth/$bin | tee $wrkpth/Binwalk/$prj_name-binwalk_output-$current_time.txt 2> /dev/null
cd $pth
echo 

# Placeholder
echo "--------------------------------------------------"
echo "Running cve-bin-tool"
cd $wrkpth/cve-bin-tool/
cve-bin-tool -i $pth/$bin -o $wrkpth/cve-bin-tool/$prj_name-cve-bin-tool_output-$current_time.log -c 4 2> /dev/null
cd $pth
echo 

# Fuzzing executable binary
echo "--------------------------------------------------"
echo "Fuzzing executable binary"
echo "--------------------------------------------------"
valgrind --tool=memcheck --leak-check=yes --show-reachable=yes --num-callers=20 --track-fds=yes --log-file=$wrkpth/Valgrind/$prj_name-valgrind_output-$current_time.log --verbose ./$bin 2> /dev/null | tee -a $wrkpth/Valgrind/$prj_name-valgrind_output-$current_time.txt
zzuf -s 0:1000000 -c -C 0 -q -T 3 objdump -x $bin | tee -a $wrkpth/Zzuf/$prj_name-zzuf_output-$current_time.log  # https://fuzzing-project.org/tutorial1.html
echo
} 2> /dev/null | tee -a $wrkpth/$prj_name-binspector_output-$current_time.txt

# Cleaning up
echo "--------------------------------------------------"
echo "Cleaning house"
echo "--------------------------------------------------"
rm -rf $wrktmp/
find $wrkpth -type d,f -empty | xargs rm -rf
zip -ru9 $pth/$prj_name-binspector-$current_time.zip $wrkpth/*
echo "All done!"