#!/bin/bash

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
    asnEnum
    subdomainEnum
    httpResolve
    portScan
}

print_usage() { 
    printf "Usage: enumerate.sh -a [ASN] -c [CIDR] -m [passive|active]\n"
}

initializeVariables(){
    # Files
    currentDirectory=$(pwd)
    target="BankWest"
    topLevelDomains="$currentDirectory/topLevelDomains.txt"
    subdomains="$currentDirectory/subDomains.txt"
    hosts="$currentDirectory/hosts.txt"

    # Variables
    rateLimit="100"
    commonports="66,80,81,443,445,457,1080,1100,1241,1352,1433,1434,1521,1944,2301,3000,3128,3306,4000,4001,4002,4100,5000,5432,5800,5801,5802,6346,6347,7001,7002,8000,8080,8443,8888,30821"
}

asnEnum() {
    echo -e "\033[31mStarting passive ASN enumeration on $target\033[0m"
    amass intel -asn $asn 2>/dev/null
    amass db -names -d bankwest.com.au | anew hosts.txt

    if [[ $mode == "active" ]]
    then
        echo -e "\033[31mStarting active ASN enumeration on $target\033[0m"
        amass intel -active -asn $asn -p $commonports
        amass db -names -d bankwest.com.au | anew hosts.txt
    fi

    #Clean TopLevelDomains here
}

subdomainEnum(){
    echo -e "\033[31mStarting passive subdomain enumeration on $target\033[0m"
    while IFS= read -r domain; do
        subfinder -d $domain -silent | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        amass enum -d $domain -passive -silent
        amass db -names -d $domain | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        assetfinder -subs-only $domain -df /usr/share/amass/wordlists/all.txt | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        #Testing output from this command before adding to script
        #amass intel -whois -d $domain | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
    done < $topLevelDomains


    if [[ $mode == "active" ]]
    then
        echo -e "\033[31mStarting active subdomain enumeration on $target\033[0m"
        while IFS= read -r domain; do
            amass enum -active -d $domain -p $commonports -rqps $rateLimit | grep -v '[@*:]' | grep "\.$domain" | anew $subdomains
        done < $topLevelDomains
    fi
}

httpResolve(){
    echo -e "\033[31mStarting Http Resolve on $target\033[0m"
    cat "$subdomains" | httprobe -c 20 | anew "$hosts" 
}

portScan(){
    if [[ -n $cidr && $mode == "active" ]]; then
        sudo masscan $cidr -p-
    fi
}

nucleiScan(){

}

main "$@"