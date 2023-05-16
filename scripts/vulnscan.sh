#!/bin/bash

domain=$1

echo "################ Scanning for $domain please wait ..."  
nuclei -u $domain -nc -mr 1 -rl 75 -timeout 5 -mhe 10  
echo "################ Scan finished successfully"
echo "################ Thanks for using"