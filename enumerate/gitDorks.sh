#!/bin/bash

# exampleCompany.com
site=$1
# exampleCompany
company=$2
github="https://github.com/search?q="
type="&type=Code"
keywords=("password" "npmrc%20_auth" "dockercfg" "pem%20private" "extension:pem%20private" "id_rsa" "aws_access_key_id" "s3cfg" "htpasswd" "git-credentials" "bashrc%20password" \
        "SECRET_KEY" "client_secret" "sshd_config" "github_token" "api_key" "FTP" "app_secret" "passwd" ".env" ".exs" "beanstalkd.yml" "deploy.rake" "mysql" "credentials" "bash_history" \
        ".sls" "PWD" "secrets" "composer.json" )

for keyword in "${keywords[@]}"; do
    echo "$github$site+$keyword$type" | anew gitDorks.txt
    echo "$github$company+$keyword$type" | anew gitDorks.txt
done

#Extend tool to make requests, save response data, and parse output for interesting output. 

