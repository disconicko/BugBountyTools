#!/bin/bash
#Global variables
targetName=$(basename "$(pwd)")
target=$(basename "$targetDirectory")
originalScope="$targetDirectory/originalScope.txt"
wildcards="$targetDirectory/wildcards.txt"
subdomains="$targetDirectory/subdomains.txt"
hosts="$targetDirectory/hosts.txt"
newSubdomains="$targetDirectory/newSubdomains.txt"
newHosts="$targetDirectory/newHosts.txt"

main(){
    echo "Starting Monitor on $targetName"

    #Empty the files below
    > "$newSubdomains"
    > "$newHosts"
    > "$vulnerabilties"

    nuclei -ut -silent
    enumSubdomains
    httpResolve
    enumSSLNames
    cleanFiles
    nucleiScan
    notifyBot
    echo "Finished Monitor on $targetName"
}

#updateTemplates
nucleiUpdate(){
    nuclei -ut
}

#performs subdomain enumeration on the wildcards
enumSubdomains(){
    echo "Starting Subdomain Enumeration on $targetName"
    while IFS= read -r wildcard; do
      subfinder -d $wildcard -silent | grep -v '[@*:]' | grep "\.$wildcard" | anew $subdomains | anew $newSubdomains
      amass enum -d $wildcard -passive -silent | grep -v '[@*:]' | grep "\.$wildcard" | anew $subdomains | anew $newSubdomains
      assetfinder -subs-only $wildcard -df /usr/share/amass/wordlists/all.txt | grep -v '[@*:]' | grep "\.$wildcard" | anew $subdomains | anew $newSubdomains
    done < $wildcards
}

#Runs http probe on targets. May need to eventually to full port scans to find high port http pages
httpResolve(){
    echo "Starting Http Resolve on $targetName"
    cat "$subdomains" | httprobe -c 20 --prefer-https | anew "$hosts" | anew "$newHosts"
}

#Searches SSL certs for subdomains and wildcards
enumSSLNames(){
    echo "Starting SSL Cert Enumeration on $targetName"
    nuclei -l $hosts -t ssl/ssl-dns-names.yaml -silent | \
      grep -oP '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | grep -v '[*@:]' | grep -v '^\.' | anew $subdomains 1>/dev/null

    nuclei -l $hosts -t ssl/wildcard-tls.yaml -silent | grep -oP '\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | \
      sed 's/^\*\.//' | anew $wildcards 1>/dev/null
}

#Runs nuclei scans on http resolved targets
nucleiScan(){
    echo "Starting Nuclei Scans on $targetNam"
    nuclei -l "$newSubdomains" -severity low,medium,high,critical -silent | anew $vulnerabilities
    nuclei -l "$newHosts" -severity low,medium,high,critical -silent | anew $vulnerabilities
}

#Sends Discord messages whenever new subdomains, hosts or vulnerabilities are found.
notifyBot(){
    if [$(wc -l <"${newsubDomains}") != 0]; then
        cat "${newSubdomains}" | notify -silent -id subdomain

    if [$(wc -l <"${newHosts}") != 0]; then
        cat "${newHosts}" | notify -silent -id resolve

    if [$(wc -l <"${vulnerabilities}") != 0]; then
        cat "${vulnerabilties}" | notify -silent -id nuclei
}

#Removes any unwanted/out-of-scope domains from the file
cleanFiles(){
    cleanedDomains=()
    cleanedHosts=()
    cleanedWildcards=()

    while IFS= read -r wildcard; do
        while IFS= read -r scope; do
            if [[ "$wildcard" =~ (^|\.)"$scope"$ ]]; then
                cleanedWildcards+=("$wildcard")
                break
            fi
        done < "$originalScope"
    done < "$wildcards"

    while IFS= read -r subdomain; do
        while IFS= read -r scope; do
            if [[ "$subdomain" =~ (^|\.)"$scope"$ ]]; then
                cleanedDomains+=("$subdomain")
                break 
            fi
        done < "$originalScope"
    done < "$subdomains"

    while IFS= read -r host; do
        while IFS= read -r scope; do
            if [[ "$host" =~ (^|\.)"$scope"$ ]]; then
                cleanedHosts+=("$host")
                break
            fi
        done < "$originalScope"
    done < "$hosts"

    > "$wildcards"
    for wildcard in "${cleanedWildcards[@]}"; do
        echo "$wildcard" >> "$wildcards"
    done

    > "$subdomains"
    for subdomain in "${cleanedDomains[@]}"; do
        echo "$subdomain" >> "$subdomains"
    done

    > "$hosts"
    for host in "${cleanedHosts[@]}"; do
        echo "$host" >> "$hosts"
    done
}

main
