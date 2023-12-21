#!/bin/bash

main(){
    initializeVariables "$@"
    #gitDork
}

initializeVariables(){
    site=$1
    company=$2
    githubToken=$3

    github="https://github.com/search?q="
    githubAPI="https://api.github.com/search/code?q="
    type="&type=Code"
    keywords=("password" "npmrc%20_auth" "dockercfg" "pem%20private" "extension:pem%20private" "id_rsa" "aws_access_key_id" "s3cfg" "htpasswd" "git-credentials" "bashrc%20password" \
            "SECRET_KEY" "client_secret" "sshd_config" "github_token" "api_key" "FTP" "app_secret" "passwd" ".env" ".exs" "beanstalkd.yml" "deploy.rake" "mysql" "credentials" "bash_history" \
            ".sls" "PWD" "secrets" "composer.json" )
    gitDorks=()
    for keyword in "${keywords[@]}"; do
        echo "$github$company+$keyword$type" | anew gitDorks.txt
        echo "$github$site+$keyword$type" | anew gitDorks.txt

        gitDorks+=("$githubAPI$company+$keyword$type")
        gitDorks+=("$githubAPI$site+$keyword$type")
    done
}

# Extend tool to make requests, save response data, and parse output for interesting output. 
# Need to research the gitAPI documentation to learn how to process the output. 
gitDork(){
    for dork in "${gitDorks[@]}"; do
        curl -H "Authorization: token $githubToken" "$dork"
    done
}

main "$@"
