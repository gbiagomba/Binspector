#!/usr/bin/env bash
# Checking dependencies - peframe, zzuf, valgrind

# Setting up variables
OS_CHK=$(cat /etc/os-release | grep -o debian)

# Checking user is root
if `echo $EUID` -ne 0
  then echo "Please run as root"
  exit
fi

# Ensuring system is debian based
if "$OS_CHK" != "debian"; then
    echo "Unfortunately this install script was written for debian based distributions only, sorry!"
    exit
fi

# Installing cve-bin-tool
if ! cve-bin-tool; then
    pip3 install cve-bin-tool
fi

# Installing peframe
if ! peframe; then
    pip3 install peframe
    if ! peframe; then
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
if ! binwalk; then
    apt install binwalk -y
    if ! binwalk; then
        git clone https://github.com/ReFirmLabs/binwalk
        cd binwalk
        python3 setup.py install
    fi
fi

# Installing zzuf
if ! /usr/bin/zzuf; then
    apt install zzuf -y
fi

# Installing valgrind
if ! /usr/bin/valgrind; then
    apt install valgrind -y
    if ! /usr/bin/valgrind; then
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
