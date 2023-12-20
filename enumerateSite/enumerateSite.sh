#!/bin/bash

while IFS= read -r target; do
    stripped_url=$(echo "$target"| sed 's#http[s]\?://##')

    #nuclei -u $target -silent | anew "$target_directory/nucleiVulns"
    echo $target | hakrawler -d 10 | grep -i "^$target" | anew "paths"
    paramspider -d $stripped_url -s 2>/dev/null | grep -i $target | anew "paths"
    cat "paths" | unfurl format %d%p | anew "sitemap"
    rm -r ./results 2>dev/null
    cat "paths" | unfurl "keys" | anew "paramsWordlist"
    cat "paths" | unfurl "paths" | anew "pathsWordlist"
done < hosts.txt

