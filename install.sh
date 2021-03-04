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

# Installing cve-bin-tool
if [ ! hash cve-bin-tool ];
    pip3 install cve-bin-tool
fi

# Installing peframe
if [ ! hash peframe ]; then
    apt install peframe -y
    if [ ! hash peframe ]; then
        cd /opt/
        git clone https://github.com/guelfoweb/peframe
        cd peframe/
        pip3 install -r requirements.txt
        python3 setup.py install
        bash.install
    fi
fi

# Installing binwalk
if [ ! hash binwalk ]
    apt install binwalk -y
    if [ ! hash binwalk ]
        git clone https://github.com/ReFirmLabs/binwalk
        cd binwalk
        python3 setup.py install
    fi
fi

# Installing zzuf
if [ ! hash /usr/bin/zzuf ]; then
    apt install zzuf -y
fi

# Installing valgrind
if [ ! hash /usr/bin/valgrind ]; then
    apt install valgrind -y
    if [ ! hash /usr/bin/valgrind ]; then
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
