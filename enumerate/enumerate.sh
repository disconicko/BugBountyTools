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
    #githubEnum
    #wayBackUrls
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
    if [ -z $output ]; then
        printf "Please provide a target output directory"
        print_usage
        exit 1
    fi

    outputDirectory=$output
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
    redOpen="\033[31m"
    colourClose="\033[0m"
    blueOpen="\033[33m"
    greenOpen="\033[32m"
    gitToken=""

    #Directories for file storage
    mkdir $outputDirectory/Enumeration 2>/dev/null
    mkdir $outputDirectory/InformationGathering 2>/dev/null
    mkdir $outputDirectory/VulnerabilityScanning 2>/dev/null    

    #Print Banner
    figlet -t -k -f /usr/share/figlet/small.flf "Enumerate" 
     

}

asnEnum() {
    if [ -z $asn ]; then
        echo -e "$redOpen Starting Passive ASN Enumeration $colourClose"
        amass intel -asn $asn | anew $topLevelDomains
        echo -e "$greenOpen Finished Passive ASN Enumeration $colourClose"
    else 
        echo -e ""$redOpen No ASN Provided. Skipping ASN Enumeration $colourClose""
    fi
}

subdomainEnum(){
    echo -e "$redOpen Starting Passive Subdomain Enumeration $colourClose"

    if [ ! -s "$topLevelDomains" ]; then
        echo "No Top Level Domains In topLevelDomains.txt"
        echo "Quitting"
        exit 1
    fi

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
        nuclei -l $subdomains -t ssl/ssl-dns-names.yaml -silent -rl $rateLimit | grep -oP '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sed 's/^\.//' | \
            grep -f $topLevelDomains | anew $subdomains | httprobe | anew $hosts &\
        nuclei -l $subdomains -t ssl/wildcard-tls.yaml -rl $rateLimit -silent | grep -oP '\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sed 's/^\*\.//' | \
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
    elif [[ -z $cidr ]]; then
        echo -e "$redOpen No CIDR Provided. Skipping Port Scan $colourClose"
    fi
}

#Resolves domains with interesting ports rather than IP addresses
#This will take a long time
commonPortScan(){
    if [[ $mode == "active" ]]; then
        cat $subdomains | httprobe -p http:8080 -p http:8000 -p http:8888 -p http:8081\
         -p http:8008 -p http:8082 -p http:81 -p http:8083 -p http:82 -p http:8084 -p http:8001\
          -p http:8090 -p http:83 -p http:8085 -p http:8088 -p http:8002 -p http:8089 -p http:84\
           -p http:8091 -p http:85 -p http:8003 -p http:8092 -p http:8004 -p http:8093 -p http:86\
            -p http:8094 -p http:8005 -p http:8095 -p http:8006 -p http:8096 -p http:8007 -p http:8097\
             -p http:8009 -p http:8098 -p http:88 -p http:8099 -p http:8010 -p http:8100 -p http:8011\
              -p http:8101 -p http:8012 -p http:8102 -p http:8013 -p http:8103 -p http:8014 -p http:8104\
               -p https:8443 -p https:8080 -p https:8000 -p https:8888 -s | anew $hosts
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
    if [[ -n $cidr && $mode == "active" ]]; then
        echo -e "$redOpen Starting Service Scan With Nmap $colourClose"
        nmapFormat="${cidr//,/' '}"
        nmap $nmapFormat -sV -T4 -F -oG $nmapOutput  
        echo -e "$greenOpen Finished Service Scan With Nmap $colourClose"

        echo -e "$redOpen Starting Credential Spraying $colourClose"
        brutespray -f $nmapOutput -q
        echo -e "$greenOpen Finished Credential Spraying $colourClose"
    elif [[ -z $cidr ]]; then
        echo -e "$redOpen No CIDR Provided. Skipping Service Scan $colourClose"
    fi
}

main "$@"