#!/bin/bash

#Install Go
# First, install the package
#sudo apt install -y golang
#Make sure the binary path is in your home folder not root folder.

# Then add the following to your .bashrc or .zshrc
#export GOROOT=/usr/lib/go
#export GOPATH=$HOME/go
#export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
#source .bashrc

#Install Masscan
#Comes with Kali. Check for installation

#Install Amass
echo "Installing Amass"
go install -v github.com/owasp-amass/amass/v4/...@master
if [ $? -eq 0 ]; then
    echo "Amass Installation successful."
else
    echo "Amass Installation failed."
fi

#Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
if [ $? -eq 0 ]; then
    echo "Nuclei Installation successful."
else
    echo "Nuclei Installation failed."
fi

#Install Tomnomnom tools
echo "Installing Httprobe"
go install -v github.com/tomnomnom/httprobe@latest
if [ $? -eq 0 ]; then
    echo "Httprobe Installation successful."
else
    echo "Httprobe Installation failed."
fi

#Install Assetfinder
echo "Installing Assetfinder"
go install -v github.com/tomnomnom/assetfinder@latest
if [ $? -eq 0 ]; then
    echo "Assetfinder Installation successful."
else
    echo "Assetfinder Installation failed."
fi

#Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
if [ $? -eq 0 ]; then
    echo "Subfinder Installation successful."
else
    echo "Subfinder Installation failed."
fi

#Install Anew
echo "Installing Anew"
go install -v github.com/tomnomnom/anew@latest
if [ $? -eq 0 ]; then
    echo "Anew Installation successful."
else
    echo "Anew Installation failed."
fi

#Install Hakrawler
go install github.com/hakluke/hakrawler@latest
if [ $? -eq 0 ]; then
    echo "Hakrawler Installation successful."
else
    echo "Hakrawler Installation failed."
fi

#Install Httprobe
go install github.com/tomnomnom/httprobe@latest
if [ $? -eq 0 ]; then
    echo "Httprobe Installation successful."
else
    echo "Httprobe Installation failed."
fi

#Install FFF
go install github.com/tomnomnom/fff@latest
if [ $? -eq 0 ]; then
    echo "fff Installation successful."
else
    echo "fff Installation failed."
fi

#Install GF
go install github.com/tomnomnom/gf@latest
if [ $? -eq 0 ]; then
    echo "GF Installation successful."
else
    echo "GF Installation failed."
fi

mkdir ~/.gf
json_content='{
    "flags": "-hroiE",
    "pattern": "^\u003c [a-z0-9_\\-]+: .*"
}'
echo "$json_content" > ~/.gf/meg-headers.json

#Install Unfurl
go install github.com/tomnomnom/unfurl@latest
if [ $? -eq 0 ]; then
    echo "Unfurl Installation successful."
else
    echo "Unfurl Installation failed."
fi

#Install github-subdomains
go install github.com/gwen001/github-subdomains@latest
if [ $? -eq 0 ]; then
    echo "github-subdomains Installation successful."
else
    echo "github-subdomains Installation failed."
fi

#Install WaybackUrls
go install github.com/tomnomnom/waybackurls@latest
if [ $? -eq 0 ]; then
    echo "WaybackUrls Installation successful."
else
    echo "WaybackUrls Installation failed."
fi

#Install Brutespray
sudo apt-get install brutespray
if [ $? -eq 0 ]; then
    echo "Brutespray Installation successful."
else
    echo "Brutespray Installation failed."
fi

echo "Installation script complete. Check for errors"

