# Enumerate 
Enumerate is designed to enumerate targets top-down starting with their ASN number and CIDR ranges. To get the most out of this tool, please add your API keys to the Amass datasources.yaml file. 
For more information please see: 
https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md

## Before Running
This script requires several tools and a Go installation. If Go is not installed, please see: https://go.dev/doc/install

To install the tools required, run the install.sh script. This will install the following tools:
* Anew
* Amass
* Assetfinder
* Httprobe
* Subfinder
* Masscan
* Nuclei
* Github-subdomains

If these tools are not working in the command line, ensure that their binaries are in the Go binary path and that the binary path has been added to the $PATH.

## Running
Usage: 
```
./enumerate.sh -a [ASN] -c [CIDR] -m [passive|active] -o [output Directory]
```

Modes:
Passive:
* Non-intrusive ASN lookups
* Top-level domain discovery
* Subdomain discovery
* GitHub crawling

Active:
Performs all Passive functions and adds:
* Port scanning
* Vulnerability scanning with Nuclei and Nikto
* Active subdomain enumeration
* Site crawling
* Default credential bruteforcing

The tool uses resources such as Wayback Machine, Whois, DNS Zone Transfers, certificate scraping, and more.

## TODO
* Organise output into sorted folders **DONE**
* Add checks against known in-scope top level domains to avoid falling out of scope. **DONE** 
* Add checks to resolve hosts to their IP. Check IP against in range CIDR to avoid falling out of scope. 
* Add Github Dorking tool. **DONE**
* Add certificate scraping for subdomains. **DONE** 
* Add default credentiaal scanner. **DONE**
* Add Port scanning. Either Masscan or Nmap (tuned). Need to find a tool with a clean output. All port scans will be rate limited. **DONE**
* Add option to screen-shot all valid HTTP services for fast enumeration. 
* Add option to discover all IIS servers (with custom Nuclei Template). These are likely vulnerable to shortname scanning. **DONE**
* Potential: This tool could be put into a Cronjob and could permanently monitor targets for changes in infrastructure.
