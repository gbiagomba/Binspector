#!/usr/bin/env bash
# Checking dependencies - peframe, zzuf, valgrind

# Setting up variables
OS_CHK=$(cat /etc/os-release | grep -o debian)

# Checking user is root
if [ `echo $EUID` -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Ensuring system is debian based
if [ "$OS_CHK" != "debian" ]; then
    echo "Unfortunately this install script was written for debian based distributions only, sorry!"
    exit
fi

# Installing cve-bin-tool
if ! hash cve-bin-tool 2> /dev/null; then
    pip3 install cve-bin-tool
fi

# Installing peframe
if ! hash peframe 2> /dev/null; then
    pip3 install peframe
    if ! hash peframe 2> /dev/null; then
        cd /opt/
        git clone https://github.com/guelfoweb/peframe
        cd peframe/
        chmod +x install.sh setup.py
        bash install.sh
        pip3 install -r requirements.txt
        python3 setup.py bdist_wheel
        python3 setup.py install
        bash.install
    fi
fi

# Installing binwalk
if ! hash binwalk 2> /dev/null; then
    apt install binwalk -y
    if ! hash binwalk 2> /dev/null; then
        git clone https://github.com/ReFirmLabs/binwalk
        cd binwalk
        python3 setup.py install
    fi
fi

# Installing zzuf
if ! hash zzuf 2> /dev/null; then
    apt install zzuf -y
fi

# Installing valgrind
if ! hash valgrind 2> /dev/null; then
    apt install valgrind wget -y
    if ! hash valgrind 2> /dev/null; then
        wget -q https://sourceware.org/pub/valgrind/valgrind-3.16.1.tar.bz2
        cd valgrind-3.16.1
        ./configure
        make
        make install
    fi
fi

# Downloading the Vulners Nmap Script
ln -s /opt/Binspector/binspector.sh /usr/bin/binspector

# Done
echo finished!
