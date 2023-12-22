#!/bin/bash

#TODO Add Proxy wrapper
#TODO Port scan

main () {
    while getopts ':a:c:m:' flag; do
        case "${flag}" in 
            a) 
                asn="${OPTARG}" ;;
            c) 
                cidr="${OPTARG}" ;;
            m)
                mode="${OPTARG}" ;;
            *) 
                print_usage
                exit 1 ;;
        esac
    done

    initializeVariables

    # Phase 1 Enumeration
    echo -e "$redOpen Starting Phase 1 - Enumeration on $target $redClose"
    asnEnum
    subdomainEnum
    githubEnum
    wayBackUrls
    httpResolve
    crawl
    echo -e "$redOpen Finished Phase 1 - Enumeration on $target $redClose"
    
    # Phase 2 Information Gathering
    echo -e "$redOpen Starting Phase 2 - Information Gathering on $target $redClose"
    iisDiscovery
    getHeaders
    serviceScan
    #portScan
    echo -e "$redOpen Finished Phase 2 - Information Gathering on $target $redClose"

    # Phase 3 Vulnerability Scanning
    echo -e "$redOpen Starting Phase 3 - Vulnerability Scanning on $target $redClose"
    #Nuclei scans are likely to get your IP Banned by Akamai. Find a way to obfuscate scans if possible.
    #Add check for Akamai IP ban error. 
    #nucleiScan 
    #niktoScan
    echo -e "$redOpen Finished Phase 3 - Vulnerability Scanning on $target $redClose"
    echo -e "$redOpen Script finished - Happy Hacking $redClose"
}

print_usage() { 
    printf "Usage: enumerate.sh -a [ASN] -c [CIDR] -m [passive|active]\n"
}

initializeVariables(){
    #Directories for file storage
    mkdir Enumeration
    mkdir InformationGathering
    mkdir VulnerabilityScanning

    # Files for output
    currentDirectory=$(pwd)
    target="Example Target"
    topLevelDomains="$currentDirectory/topLevelDomains.txt"
    subdomains="$currentDirectory/Enumeration/subDomains.txt"
    hosts="$currentDirectory/Enumeration/hosts.txt"
    unconfirmedTopLevelDomains="$currentDirectory/InformationGathering/unconfirmedTopLevelDomains.txt"
    iisServers="$currentDirectory/InformationGathering/iisServers.txt"
    nmapOutput="$currentDirectory/InformationGathering/nmap.out"
    vulnerabilities="$currentDirectory/VulnerabilityScanning/vulnerabilities.txt"

    # Files for outputting custom wordlists
    paths="$currentDirectory/InformationGathering/pathsWordlist.txt"
    variables="$currentDirectory/InformationGathering/variablesWordlist.txt"

    # Variables
    rateLimit="100"
    commonPorts="21,22,23,66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3000,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8000,8080,8443,8888,30821,139,11211,110,25,3389,5900"
    redOpen="\033[31m"
    redClose="\033[0m"
    gitToken=""
}

asnEnum() {
    echo -e "$redOpen Starting passive ASN enumeration on $target $redClose"
    amass intel -asn $asn 2>/dev/null

    while IFS= read -r domain; do
        amass db -names -d $domain | anew $subdomains
    done < $topLevelDomains
}

subdomainEnum(){
    echo -e "$redOpen Starting passive subdomain enumeration on $target $redClose"
    while IFS= read -r domain; do
        echo -e "$redOpen Starting subdomain enumeration on $domain $redClose"
        subfinder -d $domain -silent | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        amass enum -d $domain -passive -silent
        amass db -names -d $domain | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        assetfinder -subs-only $domain -df /usr/share/amass/wordlists/all.txt | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        amass intel -whois -d $domain | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
    done < $topLevelDomains

    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting active subdomain enumeration on $target $redClose"

        #Taking too long. Find a way to reduce requests.
        while IFS= read -r domain; do
            amass enum -active -d $domain -rqps $rateLimit | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        done < $topLevelDomains

        #Custom Cert scraping
        echo -e "$redOpen Starting SSL Cert Enumeration on $target $redClose"
        nuclei -l $subdomains -t ssl/ssl-dns-names.yaml -silent | grep -oP '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sed 's/^\.//' | \
            grep -f $topLevelDomains | anew $subdomains | httprobe | anew $hosts 

        #This will output new wildcard domains from certs. These domains are likely out of scope. Review manually. 
        nuclei -l $subdomains -t ssl/wildcard-tls.yaml -silent | grep -oP '\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sed 's/^\*\.//' | \
            anew $unconfirmedTopLevelDomains | anew $subdomains | httprobe | anew $hosts
    fi
}

wayBackUrls(){
    echo -e "$redOpen Starting Wayback Machine enumeration on $target $redClose"
    while IFS= read domain; do
        echo $domain | waybackurls | unfurl domains | anew $subdomains
    done < $subdomains
}

githubEnum(){
    echo -e "$redOpen Starting Github Scan on $target $redClose"
    if [[ -n $gitToken ]]; then
        while IFS= read -r domain; do
        github-subdomains -d $domain -raw -t $gitToken | anew $subdomains
        done
    else
        echo -e "$redOpen No GitToken. Skipping Github Enumeration $redClose"
    fi
}

httpResolve(){
    echo -e "$redOpen Starting Http Resolve on $target $redClose"
    cat "$subdomains" | httprobe -c 20 | anew "$hosts" 
}

crawl(){
    if [[ $mode == "active" ]]; then
       cat $hosts | hakrawler -insecure -subs -u -d 5 | unfurl format %s://%d | grep -f $topLevelDomains | anew $hosts
    fi
}

getHeaders(){
    if [[ $mode == "active" ]]; then
        cat $hosts | fff -d 5 -S -o $currentDirectory/InformationGathering/roots
        gf meg-headers | anew headers
        sort headers
    fi
}

portScan(){
    if [[ -n $cidr && $mode == "active" ]]; then
        echo -e "$redOpen Starting Port on $target $redClose"
        sudo masscan $cidr -p-
    fi
}

nucleiScan(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Nuclei Scans on $target $redClose"
        nuclei -l "$subdomains" -severity high,critical -rl 10 -c 2 -silent | anew $vulnerabilities
        nuclei -l "$hosts" -severity high,critical -rl 10 -c 2 -silent | anew $vulnerabilities
    fi
}

iisDiscovery(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting IIS Discovery on $target $redClose"
        nuclei -l "$hosts" -t "./CustomTemplates/enhanced-iis-discovery.yaml" -rl $rateLimit -silent | anew $iisServers
    fi
}

serviceScan(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Nmap Scan on $target $redClose"
        nmapFormat="${cidr//,/' '}"
        nmap $nmapFormat -sV -T5 -F -oG $nmapOutput

        echo -e "$redOpen Starting Credential Spraying on $target $redClose"
        brutespray $nmapOutput
    fi
}

main "$@"