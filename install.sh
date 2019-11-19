#!/usr/bin/env bash
# Checking dependencies - peframe, zzuf, valgrind

# Setting up variables
OS_CHK=$(cat /etc/os-release | grep -o debian)

# Checking user is root
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Ensuring system is debian based
if [ "$OS_CHK" != "debian" ]; then
    echo "Unfortunately this install script was written for debian based distributions only, sorry!"
    exit
fi

if [ ! -x /usr/local/bin/peframe ] || [ ! -x /usr/bin/peframe ]; then
    apt install peframe -y
    if [ ! -x /usr/local/bin/peframe ] || [ ! -x /usr/bin/peframe ]; then
        cd /opt/
        git clone https://github.com/guelfoweb/peframe
        cd peframe/
        python3 setup.py install
        bash.install
    fi
fi

if [ ! -x /usr/bin/zzuf ]; then
    apt install zzuf -y
fi

if [ ! -x /usr/bin/valgrind ]; then
    apt install valgrind -y
fi

# Downloading the Vulners Nmap Script
cd /opt/
git clone https://github.com/gbiagomba/Binspector
cd /usr/bin/
ln -s /opt/Binspector/binspector.sh binspector

# Done
echo finished!
