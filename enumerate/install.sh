#!/bin/bash

#Install Go
# wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz -o /tmp/go1.21.5.linux-amd64.tar.gz
# tar -C /usr/local -xzf /tmp/go1.21.5.linux-amd64.tar.gz
#Add Go bin path
# export PATH=$PATH:/usr/local/go/bin

#Install Amass
echo "Installing Amass"
go install -v github.com/owasp-amass/amass/v4/...@master
if [ $? -eq 0 ]; then
    echo "Amass Installation successful."
else
    echo "Amass Installation failed."
fi

#Install Masscan
#TODO

#Install Nuclei
#TODO

#Install Tomnomnom tools
echo "Installing Httprobe"
go install -v github.com/tomnomnom/httprobe@latest
if [ $? -eq 0 ]; then
    echo "Httprobe Installation successful."
else
    echo "Httprobe Installation failed."
fi

echo "Installing Assetfinder"
go install -v github.com/tomnomnom/assetfinder@latest
if [ $? -eq 0 ]; then
    echo "Assetfinder Installation successful."
else
    echo "Assetfinder Installation failed."
fi

echo "Installing Anew"
go install -v github.com/tomnomnom/anew@latest
if [ $? -eq 0 ]; then
    echo "Anew Installation successful."
else
    echo "Anew Installation failed."
fi

#Install github-subdomains
#TODO

echo "Installation script complete. Check for errors"

