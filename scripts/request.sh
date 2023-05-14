domain=$1

# Request and response subdomains 
httpx -l history/$domain/subdomains.txt -timeout 2 -silent -tech-detect -ip -json -o history/$domain/httpx.json 1>/dev/null
cat history/$domain/httpx.json | jq '. | {status_code,url,host,port,tech}' | jq --slurp .