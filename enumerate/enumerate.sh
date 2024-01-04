#!/bin/bash

main () {
    while getopts ':a:c:m:o:' flag; do
        case "${flag}" in 
            a) 
                asn="${OPTARG}" ;;
            c) 
                cidr="${OPTARG}" ;;
            m)
                mode="${OPTARG}" ;;
            o)
                output="${OPTARG}" ;;
            *) 
                print_usage
                exit 1 ;;
        esac
    done

    initializeVariables

    # Phase 1 Enumeration
    echo -e "$redOpen Starting Phase 1 - Enumeration on $target $colourClose"
    asnEnum
    subdomainEnum
    githubEnum
    wayBackUrls
    httpResolve
    crawl
    echo -e "$redOpen Finished Phase 1 - Enumeration on $target $colourClose"
    
    # Phase 2 Information Gathering
    echo -e "$redOpen Starting Phase 2 - Information Gathering on $target $colourClose"
    iisDiscovery
    getHeaders
    serviceScan
    #portScan
    #commonPortScan
    echo -e "$redOpen Finished Phase 2 - Information Gathering on $target $colourClose"

    # Phase 3 Vulnerability Scanning
    echo -e "$redOpen Starting Phase 3 - Vulnerability Scanning on $target $colourClose"
    #nucleiScan 
    #niktoScan
    echo -e "$redOpen Finished Phase 3 - Vulnerability Scanning on $target $colourClose"
    echo -e "$redOpen Script finished - Happy Hacking $colourClose"
}

print_usage() { 
    printf "Usage: enumerate.sh -a [ASN] -c [CIDR] -m [passive|active] -o [Output Folder]\n"
}

initializeVariables(){

    # Files for output
    if [[ -n $output]]; do
        printf "Please provide a target output directory"
        print_usage
        quit
    fi

    outputDirectory=$output
    target="Example Target"
    topLevelDomains="$outputDirectory/topLevelDomains.txt"
    subdomains="$outputDirectory/Enumeration/subDomains.txt"
    hosts="$outputDirectory/Enumeration/hosts.txt"
    unconfirmedTopLevelDomains="$outputDirectory/InformationGathering/unconfirmedTopLevelDomains.txt"
    iisServers="$outputDirectory/InformationGathering/iisServers.txt"
    nmapOutput="$outputDirectory/InformationGathering/nmap.out"
    vulnerabilities="$outputDirectory/VulnerabilityScanning/vulnerabilities.txt"

    # Files for outputting custom wordlists
    paths="$outputDirectory/InformationGathering/pathsWordlist.txt"
    variables="$outputDirectory/InformationGathering/variablesWordlist.txt"

    # Variables
    rateLimit="100"
    commonPorts="8080,8443,8000,8081,8008,8888,8082,81,8083,82,8084,8001,8090,83,8085,8088,8002,8089,84,8091,85,8003,8092,8004,8093,86,8094,8005,8095,8006,8096,8007,8097,8009,8098,88,8099,8010,8100,8011,8101,8012,8102,8013,8103,8014,8104,8015"
    redOpen="\033[31m"
    colourClose="\033[0m"
    greenOpen="\033[32m"
    gitToken=""

    #Directories for file storage
    mkdir $outputDirectory/Enumeration 2>/dev/null
    mkdir $outputDirectory/InformationGathering 2>/dev/null
    mkdir $outputDirectory/VulnerabilityScanning 2>/dev/null    

    #Print Banner
    echo -e "   ______                ______           __ \n  / ____/_______  ____  / ____/___ ______/ /_\n / / __/ ___/ _ \/ __ \/ /_  / __ \`/ ___/ __/\n/ /_/ / /  /  __/ /_/ / __/ / /_/ (__  ) /_  \n\\____/_/   \\___/ .___/_/    \\__,_/____/\\__/  \n              /_/                            "                     
    
}

asnEnum() {
    echo -e "$redOpen Starting Passive ASN enumeration $colourClose"
    amass intel -asn $asn | anew $topLevelDomains
    echo -e "$greenOpen Finished Passive ASN Enumeration $colourClose"
}

subdomainEnum(){
    echo -e "$redOpen Starting Passive Subdomain Enumeration $colourClose"
    while IFS= read -r domain; do
        echo -e "$redOpen Performing Passive Subdomain Enumeration On $domain $colourClose"

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
                        echo -e "$redOpen Subfinder timed out. $colourClose"
                        ;;
                    $pid_amass_enum)
                        echo -e "$redOpen Amass enum timed out. $colourClose"
                        ;;
                    $pid_amass_intel)
                        echo -e "$redOpen Amass intel timed out. $colourClose"
                        ;;
                    $pid_assetfinder)
                        echo -e "$redOpen Assetfinder timed out. $colourClose"
                        ;;
                esac
            fi
        done
    done < $topLevelDomains

    echo -e "$greenOpen Finished Passive Subddomain Enumeration $colourClose"

    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Active Subdomain Enumeration $colourClose"

        #Taking too long. Find a way to reduce requests. Probably hitting API Rate Limiting. Added Timeout
        while IFS= read -r domain; do
            echo -e "$redOpen Performing Active Subdomain Enumeration on $domain $colourClose"

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
        echo -e "$redOpen Starting SSL Cert Enumeration $colourClose"
        nuclei -l $subdomains -t ssl/ssl-dns-names.yaml -silent | grep -oP '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sed 's/^\.//' | \
            grep -f $topLevelDomains | anew $subdomains | httprobe | anew $hosts &\
        nuclei -l $subdomains -t ssl/wildcard-tls.yaml -silent | grep -oP '\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sed 's/^\*\.//' | \
            anew $unconfirmedTopLevelDomains
        wait    
        echo -e "$greenOpen Finished Active Subddomain Enumeration $colourClose"
    fi
}

wayBackUrls(){
    echo -e "$redOpen Starting Wayback Machine Enumeration $colourClose"
    while IFS= read domain; do
        echo $domain | waybackurls | unfurl domains | anew $subdomains
    done < $subdomains
    echo -e "$greenOpen Finished Wayback Machine Enumeration $colourClose"
}

githubEnum(){
    echo -e "$redOpen Starting Github Scan $colourClose"
    if [[ -n $gitToken ]]; then
        while IFS= read -r domain; do
        github-subdomains -d $domain -raw -t $gitToken | anew $subdomains
        done
    else
        echo -e "$redOpen No GitToken. Skipping Github Enumeration $colourClose"
    fi
    echo -e "$greenOpen Finished Github Scan $colourClose"
}

httpResolve(){
    echo -e "$redOpen Starting Http Resolve $colourClose"
    cat "$subdomains" | httprobe -c 20 | anew "$hosts" 
    echo -e "$greenOpen Finished Http Resolve $colourClose"
}

#Check this code. Will probably need to unfurl and httpx 
crawl(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Crawling Hosts For Subdomains $colourClose"
        cat $hosts | hakrawler -d 5 -insecure | grep -oP 'https?://[^/ ]+' | grep -f $topLevelDomains | unfurl domains | anew $subdomains | httprobe | anew $hosts
        echo -e "$greenOpen Finished Crawling Hosts For Subdomains $colourClose"
    fi
}

getHeaders(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Fetching Base Http Responses $colourClose"
        cat $hosts | fff -d 5 -S -o $outputDirectory/InformationGathering/roots
        gf meg-headers | anew $outputDirectory/InformationGathering/headers
        sort $outputDirectory/InformationGathering/headers
        echo -e "$greenOpen Finished Saving Base Http Responses $colourClose"
    fi
}

portScan(){
    if [[ -n $cidr && $mode == "active" ]]; then
        echo -e "$redOpen Starting Port Scan With Masscan $colourClose"
        sudo masscan $cidr -p-
        echo -e "$greenOpen Finished Port Scan With Masscan $colourClose"
    fi
}

#Resolves domains with interesting ports rather than IP addresses
commonPortScan(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Common Http Port Scan $colourClose"
        nmap -T4 -iL $subdomains --script=http-title --open -p $commonPorts -Pn 
        echo -e "$greenOpen Finished Common Http Port Scan $colourClose"
    fi
}

nucleiScan(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Nuclei Scans $colourClose"
        nuclei -l "$subdomains" -severity high,critical -rl 20 -c 2 -silent | anew $vulnerabilities &\
        nuclei -l "$hosts" -severity high,critical -rl 20 -c 2 -silent | anew $vulnerabilities
        wait
        echo -e "$greenOpen Finished Nuclei Scans $colourClose"
    fi
}

iisDiscovery(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting IIS Discovery $colourClose"
        nuclei -l "$hosts" -t "./CustomTemplates/enhanced-iis-detection.yaml" -rl $rateLimit -silent | anew $iisServers
        echo -e "$greenOpen Finished IIS Discovery $colourClose"
    fi
}

serviceScan(){
    if [[ $mode == "active" ]]; then
        echo -e "$redOpen Starting Service Scan With Nmap $colourClose"
        nmapFormat="${cidr//,/' '}"
        nmap $nmapFormat -sV -T4 -F -oG $nmapOutput
        echo -e "$greenOpen Finished Service Scan With Nmap $colourClose"

        echo -e "$redOpen Starting Credential Spraying $colourClose"
        brutespray -f $nmapOutput -q
        echo -e "$greenOpen Finished Credential Spraying $colourClose"
    fi
}

main "$@"