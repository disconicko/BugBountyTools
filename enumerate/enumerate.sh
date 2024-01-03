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
    nucleiScan 
    #niktoScan
    echo -e "$redOpen Finished Phase 3 - Vulnerability Scanning on $target $redClose"
    echo -e "$redOpen Script finished - Happy Hacking $redClose"
}

print_usage() { 
    printf "Usage: enumerate.sh -a [ASN] -c [CIDR] -m [passive|active]\n"
}

initializeVariables(){
    #Directories for file storage
    mkdir Enumeration 2>/dev/null
    mkdir InformationGathering 2>/dev/null
    mkdir VulnerabilityScanning 2>/dev/null

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
    commonPorts="80,443,8080,8443,8000,8081,8008,8888,8082,81,8083,82,8084,8001,8090,83,8085,8088,8002,8089,84,8091,85,8003,8092,8004,8093,86,8094,8005,8095,8006,8096,8007,8097,8009,8098,88,8099,8010,8100,8011,8101,8012,8102,8013,8103,8014,8104,8015"
    redOpen="\033[31m"
    redClose="\033[0m"
    gitToken=""
}

asnEnum() {
    echo -e "$redOpen Starting passive ASN enumeration on $target $redClose"
    amass intel -asn $asn | anew $topLevelDomains
}

subdomainEnum(){
    echo -e "$redOpen Starting passive subdomain enumeration on $target $redClose"
    while IFS= read -r domain; do
        echo -e "$redOpen Starting subdomain enumeration on $domain $redClose"

        # Run each command with a timeout in the background
        timeout 5m subfinder -d "$domain" -silent | grep -v '[@*:]' | grep "$domain$" | anew $subdomains &
        pid_subfinder=$!

        timeout 5m amass enum -d "$domain" -passive -silent | grep "$domain$" | anew $subdomains &
        pid_amass_enum=$!

        timeout 5m amass intel -whois -d "$domain" | grep "$domain$" | anew $subdomains &
        pid_amass_intel=$!

        timeout 5m assetfinder --subs-only "$domain" --df /usr/share/amass/wordlists/all.txt | grep -v '[@*:]' | grep "$domain$" | anew $subdomains &
        pid_assetfinder=$!

        # Wait for all processes and check each one
        for pid in $pid_subfinder $pid_amass_enum $pid_amass_intel $pid_assetfinder; do
            wait $pid
            exit_status=$?
            if [ $exit_status -eq 124 ]; then
                case $pid in
                    $pid_subfinder)
                        echo "Subfinder timed out."
                        ;;
                    $pid_amass_enum)
                        echo "Amass enum timed out."
                        ;;
                    $pid_amass_intel)
                        echo "Amass intel timed out."
                        ;;
                    $pid_assetfinder)
                        echo "Assetfinder timed out."
                        ;;
                esac
            fi
        done
    done < $topLevelDomains

    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting active subdomain enumeration $redClose"

        #Taking too long. Find a way to reduce requests. Probably hitting API Rate Limiting. Added Timeout
        while IFS= read -r domain; do
            echo -e "$redOpen Starting active subdomain enumeration on $domain $redClose"

            # Run amass enum with a timeout in the background
            timeout 5m amass enum -active -d $domain -silent | grep -v '[@*:]' | grep "$domain$" | anew $subdomains &
            pid_amass_enum=$!

            # Wait for the amass enum command and capture its exit status
            wait $pid_amass_enum
            exit_status=$?

            # Check the exit status
            if [ $exit_status -eq 124 ]; then
                echo "Amass enum active timed out."
            fi
        done < $topLevelDomains

        #Custom Cert scraping
        echo -e "$redOpen Starting SSL Cert Enumeration on $target $redClose"
        nuclei -l $subdomains -t ssl/ssl-dns-names.yaml -silent | grep -oP '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sed 's/^\.//' | \
            grep -f $topLevelDomains | anew $subdomains | httprobe | anew $hosts &\
        nuclei -l $subdomains -t ssl/wildcard-tls.yaml -silent | grep -oP '\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sed 's/^\*\.//' | \
            anew $unconfirmedTopLevelDomains
        wait    
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
       cat $hosts | hakrawler -insecure -d 5 | grep -oP 'https?://[^/ ]+' | grep -f $topLevelDomains | anew $hosts
    fi
}

getHeaders(){
    if [[ $mode == "active" ]]; then
        cat $hosts | fff -d 5 -S -o $currentDirectory/InformationGathering/roots
        gf meg-headers | anew $currentDirectory/InformationGathering/headers
        sort $currentDirectory/InformationGathering/headers
    fi
}

portScan(){
    if [[ -n $cidr && $mode == "active" ]]; then
        echo -e "$redOpen Starting Port on $target $redClose"
        sudo masscan $cidr -p-
    fi
}

#Resolves domains with interesting ports rather than IP addresses
commonPortScan(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting scan on subdomains to find http ports on $target $redClose"
        nmap -T4 -iL $subdomains --script=http-title --open -p $commonPorts -Pn 
    fi
}

nucleiScan(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Nuclei Scans on $target $redClose"
        nuclei -l "$subdomains" -severity high,critical -rl 20 -c 2 -silent | anew $vulnerabilities &\
        nuclei -l "$hosts" -severity high,critical -rl 20 -c 2 -silent | anew $vulnerabilities
        wait
    fi
}

iisDiscovery(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting IIS Discovery on $target $redClose"
        nuclei -l "$hosts" -t "./CustomTemplates/enhanced-iis-detection.yaml" -rl $rateLimit -silent | anew $iisServers
    fi
}

serviceScan(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Nmap Scan on $target $redClose"
        nmapFormat="${cidr//,/' '}"
        nmap $nmapFormat -sV -T4 -F -oG $nmapOutput

        echo -e "$redOpen Starting Credential Spraying on $target $redClose"
        brutespray -f $nmapOutput
    fi
}

main "$@"