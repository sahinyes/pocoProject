domain=$1



# Splitting file for js parsing
#? javascript endpoints 
#! json's should be in array 
#cat history/$domain/spider/* | grep "^\[url\]" | awk '{print $3,$5}' | jq -R 'split("\n") | .[] | select(length > 0) | {status: .[0:9]| sub("\\[|\\]"; ""), url: .[11:] | split("?")[0]}' > js.json

#Directories
#? Directories
#? Must split as form, javascript, url, subdomain, linkfinder

#cat history/$domain/spider/* | grep '^{' | jq '. | {input,type,output}' > directories.json

#? Additional features


# Subdomain Takeover
#! it must convert to json
#subzy r --targets history/$domain/subdomains.txt > history/$domain/takeover.txt 


# JS URL's 
#? 
#! It must look pretty
#cat js.json | jq .url | grep .js"$ 

# Organize output files 

#! ACTION TO GITHUB


# Phishing #! ASYNC after subdomains ca 3 min 
# dnstwist -r -s -f json history/$domain/subdomains.txt