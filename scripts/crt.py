from crtsh import crtshAPI
import json
import sys

args = sys.argv

domain = args[1]
#print(domain)

print(json.dumps(crtshAPI().search(domain)))