#!/bin/bash

domain=$1

echo "################ Scanning for $domain please wait ..."  
katana -u $domain -nc -jc -kf -timeout 5 -rl 50
echo "################ Scan finished successfully"
echo "################ Thanks for using"
