#!/usr/bin/env bash

# Cloning peframe
git clone https://github.com/guelfoweb/peframe.git
cd peframe

# Getting Linux dependencies
brew install openssl
brew install swig
env LDFLAGS="-L$(brew --prefix openssl)/lib" \
CFLAGS="-I$(brew --prefix openssl)/include" \
SWIG_FEATURES="-cpperraswarn -includeall -I$(brew --prefix openssl)/include" \
pip3 install m2crypto

# Installing the rest of the stuff
sudo python3 setup.py install
