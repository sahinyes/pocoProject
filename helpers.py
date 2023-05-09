import os
import bleach
from flask import redirect, render_template, request, session, jsonify, stream_with_context, Response
import subprocess,json
import re
from crtsh import crtshAPI
from flask_socketio import SocketIO, emit


# Apology to user
def apology(message, code=400):

    def escape(s):
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


# Sanitize input
def sanitize(param):
    sanitized = bleach.clean(param, tags=["`","'",'"',";","|","&","-","#","[","]","{","%"], attributes={}, strip=True)
    return sanitized


# Checking domain again attackers
def domainCheck(param):
    if re.match('^([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', param):        
        return param
    else:
        return False
    
def urlCheck(param):
    if re.match('^(http|https):\/\/[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$',param):
        return param
    else:
        return False

# Getting subdomains via crt
def subdomains(domain):
    result = subprocess.check_output(['scripts/recon.sh', domain]).decode('utf-8')
    output = json.loads(result)
    return output


# Scanning IP's via Shodan
def ipScan(subdomain):
    domain = re.search("([a-zA-Z0-9-]+\.[a-zA-Z]{2,})(?:\/.*)?$",subdomain).group()
    result = subprocess.check_output(['scripts/ipscan.sh', domain]).decode('utf-8')
    output = json.loads(result)
    return output


def vulnscanner(domain):
    cmd = f"scripts/vulnscan.sh {domain}"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in iter(process.stdout.readline, b''):
         #line.rstrip() + b'<br/><\n'
         yield b'<div style="color:white">' + line + b'</div>'


def dirscanner(domain):
    cmd = f"scripts/dirscan.sh {domain}"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in iter(process.stdout.readline, b''):
                 
        #line.rstrip() + b'<br/><\n'
        yield b'<div style="color:white">' + line + b'</div>'
        return(domain)
