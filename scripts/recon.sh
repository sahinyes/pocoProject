#!/bin/bash
#? gospider => go install github.com/jaeles-project/gospider@latest
#? httpx => go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
#? Subfinder => go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
#? Httprobe =>  go install github.com/tomnomnom/httprobe@latest
#? subzy => go install -v github.com/LukaSikic/subzy@latest
#? dnstwist => apt dnstwist
#? intelligenceX => https://github.com/IntelligenceX/SDK


#! TRY TO FIND ONE WAY ASYNC TASKS !!!!!


# Take input and sanitize #! w\Python
domain=$1


#Create file if its doesnt exist
#! else return logged folder 
[ ! -d $domain ] && mkdir history/$domain 2>/dev/null

# Search subdomains #! it must overwrite 

#! if its false return again 
python3 crt.py $domain && jq -r 'map(.common_name) | unique[]' > history/$domain/subdomains.txt
#subfinder -silent -d $domain > history/$domain/subdomains.txt  

# Request and response subdomains 
httpx -l history/$domain/subdomains.txt -silent -tech-detect -ip -json -o history/$domain/httpx.json 1>/dev/null
cat history/$domain/httpx.json | jq '. | {status_code,url,host,port,tech}' | jq --slurp .
