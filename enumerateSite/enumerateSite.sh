#!/bin/bash

target=$1
stripped_url=$(echo "$target"| sed 's#http[s]\?://##')
target_directory="./$stripped_url"

mkdir "$target_directory"
nuclei -u $target -silent | anew "$target_directory/nucleiVulns"
echo $target | hakrawler -d 10 | grep -i "^$target" | anew "$target_directory/paths"
paramspider -d $stripped_url -s 2>/dev/null | grep -i $target | anew "$target_directory/paths"
cat "$target_directory/paths" | unfurl format %d%p | anew "$target_directory/sitemap"
rm -r ./results
cat "$target_directory/paths" | unfurl keys | anew "$target_directory/paramsWordlist"
cat "$target_directory/paths" | unfurl paths | anew "$target_directory/pathsWordlist"

