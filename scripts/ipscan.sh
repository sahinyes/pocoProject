#!/bin/bash

domain=$1

# echo "" > history/$domain/shodan
# cat history/$domain/iplist | uniq | while read line; do curl https://internetdb.shodan.io/$line >> history/$domain/shodan 2>/dev/null; done  
# cat history/$domain/shodan | jq '. | {ip,ports}' | jq --slurp .

# cat ../history/$domain/httpx.json | jq .a[] | tr -d '"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq | 


echo "################ Scanning for $domain please wait ..."  
echo $domain | dnsx -silent -resp-only | naabu -silent -nmap-cli 'nmap -sV -v'
echo "################ Scan finished successfully"
echo "################ Thanks for using"