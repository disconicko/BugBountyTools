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
    httpResolve
    crawl
    echo -e "$redOpen Finished Phase 1 - Enumeration on $target $redClose"
    
    # Phase 2 Information Gathering
    echo -e "$redOpen Starting Phase 2 - Information Gathering on $target $redClose"
    #portScan
    iisDiscovery
    echo -e "$redOpen Finished Phase 2 - Information Gathering on $target $redClose"

    # Phase 3 Vulnerability Scanning
    echo -e "$redOpen Starting Phase 3 - Vulnerability Scanning on $target $redClose"
    #Nuclei scans are likely to get your IP Banned by Akamai.Find a way to obfuscate scans.
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
    # Files for output
    currentDirectory=$(pwd)
    target="Target"
    topLevelDomains="$currentDirectory/topLevelDomains.txt"
    subdomains="$currentDirectory/subDomains.txt"
    hosts="$currentDirectory/hosts.txt"
    vulnerabilities="$currentDirectory/vulnerabilities.txt"

    # Variables
    domain="example.com.au"
    rateLimit="100"
    commonports="66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3000,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8000,8080,8443,8888,30821"
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

    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting active ASN enumeration on $target $redClose"
        amass intel -active -asn $asn -p $commonports

        while IFS= read -r domain; do
            amass db -names -d $domain | anew $subdomains
        done < $topLevelDomains
    fi

    #Clean TopLevelDomains here
}

subdomainEnum(){
    echo -e "$redOpen Starting passive subdomain enumeration on $target $redClose"
    while IFS= read -r domain; do
        subfinder -d $domain -silent | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        amass enum -d $domain -passive -silent
        amass db -names -d $domain | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        assetfinder -subs-only $domain -df /usr/share/amass/wordlists/all.txt | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        amass intel -whois -d $domain | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
    done < $topLevelDomains

    #Taking too long. Find a way to reduce requests.
    #Might need to do the cert lookups manually with nuclei.
    #if [[ $mode == "active" ]]; then
    #    echo -e "$redOpen Starting active subdomain enumeration on $target $redClose"
    #    while IFS= read -r domain; do
            #This command takes a long time to run
    #        amass enum -active -d $domain -rqps $rateLimit | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
    #    done < $topLevelDomains
    #fi
}

githubEnum(){
    echo -e "$redOpen Starting Github Scan on $target $redClose"
    while IFS= read -r domain; do
        github-subdomains -d $domain -raw -t $gitToken | anew subdomains.txt
    done
}

httpResolve(){
    echo -e "$redOpen Starting Http Resolve on $target $redClose"
    cat "$subdomains" | httprobe -c 20 | anew "$hosts" 
}

crawl(){
    if [[ $mode == "active" ]]; then
       cat hosts.txt | hakrawler -insecure -subs -u -d 5 | unfurl format %d | grep -i $target | anew subdomains.txt
    fi
}

portScan(){
    if [[ -n $cidr && $mode == "active" ]]; then
        echo -e "$redOpen Starting Port on $target $redClose"
        #sudo masscan $cidr -p-
    fi
}

nucleiScan(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Nuclei Scans on $target $redClose"
        nuclei -l "$subdomains" -severity low,medium,high,critical -rl $rateLimit -silent | anew $vulnerabilities
        nuclei -l "$hosts" -severity low,medium,high,critical -rl $rateLimit -silent | anew $vulnerabilities
    fi
}

iisDiscovery(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting IIS Discovery on $target $redClose"
        nuclei -l "$hosts" -template "./CustomTemplates/enchanced-iis-discovery.yaml" -rl $rateLimit -silent | anew iisServers.txt
    fi
}



main "$@"