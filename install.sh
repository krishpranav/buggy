#!bin/bash

BLUE='\033[94m'
RED='\033[91m'



echo -e "$BLUE[*]$RESET Installing buggy... $RESET"
sudo apt update
sudo apt-get install -y python3 python3-requests python3-pip python3-lxml python3-requests openssl ca-certificates python3-dev wget git
cp -f $PWD/buggy.py /usr/bin/buggy
cp -f $PWD/buggy2.py /usr/bin/buggy2.py
cp -f $PWD/buggy.desktop /usr/share/applications/

echo -e "$BLUE[*]$RESET Done! $RESET"
echo -e "$RED[>]$RESET To run, type 'buggy'! $RESET"
