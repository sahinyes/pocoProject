#!/bin/bash
#dnsx
#katana
#naabu
#? httpx => go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
#? Subfinder => go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
#? subzy => go install -v github.com/LukaSikic/subzy@latest



domain=$1


#Create file if its doesnt exist 
[ ! -d $domain ] && mkdir history/$domain 2>/dev/null


# This api dosent work stabile 
#python3 scripts/crt.py $domain && jq -r 'map(.common_name) | unique[]' > history/$domain/subdomains.txt


subfinder -silent -d $domain > history/$domain/subdomains.txt  

# Request and response subdomains 
httpx -l history/$domain/subdomains.txt -timeout 2 -silent -tech-detect -ip -json -o history/$domain/httpx.json 1>/dev/null
cat history/$domain/httpx.json | jq '. | {status_code,url,host,port,tech}' | jq --slurp .