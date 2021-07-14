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

# Updating dependencies
if hash apt 2> /dev/null; then
    apt update
    for i in tar wget git python3 python3-pip peframe binwalk zzuf valgrind golang; do apt install -y $i; done
fi

# Installing virustotal
if ! hash vt 2> /dev/null; then
    cd /opt/
    git clone https://github.com/VirusTotal/vt-cli
    make install
    vt init
    vt completion bash > /etc/bash_completion.d/vt
fi

# Installing metadefender.com
if ! hash mdcloud-go 2> /dev/null; then
    if hash go; then
        go get -u -v github.com/OPSWAT/mdcloud-go
    elif hash curl && ! hash mdcloud-go; then
        curl -s https://github.com/OPSWAT/mdcloud-go/releases/download/1.2.0/mdcloud-go_linux_amd64 --output /usr/bin/mdcloud-go && chmod +x /usr/bin/mdcloud-go
    elif hash wget && [ ! -e /usr/bin/mdcloud-go ]; then
        wget -q https://github.com/OPSWAT/mdcloud-go/releases/download/1.2.0/mdcloud-go_linux_amd64 -O /usr/bin/mdcloud-go && chmod +x /usr/bin/mdcloud-go
    fi
    echo "Register an account with metadefender.com, if you dont already own one"
    for i in firefox chrome; do if hash $i; then $i https://id.opswat.com/register; fi; done
    sleep 180
    echo "What is your OPSWAT API key?"; read OPSWAT_APIKEY
    echo "# OPSWAT API Key
    export MDCLOUD_APIKEY=$OPSWAT_APIKEY" >> ~/.bashrc
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
    git clone https://github.com/ReFirmLabs/binwalk
    cd binwalk
    python3 setup.py install
fi

# Installing zzuf
if ! hash zzuf 2> /dev/null; then
    git clone https://github.com/samhocevar/zzuf
    cd zzuf
    make && make install
fi

# Installing valgrind
if ! hash valgrind 2> /dev/null; then
    wget https://sourceware.org/pub/valgrind/valgrind-3.17.0.tar.bz2
    tar -xf valgrind-3.17.0.tar.bz2
    if [ -d valgrind-3.17.0 ]; then 
        cd valgrind-3.17.0/
        chmod +x autogen.sh
        ./autogen.sh
        ./configure
        make
        make install
    elif ! hash valgrind 2> /dev/null; then
        git clone git://sourceware.org/git/valgrind.git
        cd valgrind/
        chmod +x autogen.sh
        ./autogen.sh
        ./configure
        make
        make install
    fi
fi

# Downloading the Vulners Nmap Script
if ! -e /usr/bin/binspector; then ln -s /opt/Binspector/binspector.sh /usr/bin/binspector; fi

# Done
echo finished!
