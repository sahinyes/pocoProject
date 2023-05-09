#!/bin/bash
domain=$1

echo "" > history/$domain/shodan
cat history/$domain/iplist | uniq | while read line; do curl https://internetdb.shodan.io/$line >> history/$domain/shodan 2>/dev/null; done  
cat history/$domain/shodan | jq '. | {ip,ports}' | jq --slurp .