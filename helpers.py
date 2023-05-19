import bleach
from flask import render_template
import subprocess,json
import re
from werkzeug.security import check_password_hash, generate_password_hash
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr



# DynamoDB Configurations
dynamodb = boto3.resource('dynamodb', region_name='eu-central-2')
table = dynamodb.Table('bloguser')



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



# Login sanitizer function
def sanitize_login_input(param):        
    sanitized_string = re.sub('[^a-zA-Z0-9]', '', param)
    return sanitized_string



# Register the user with username and password
def register_user(username, password):
    try:
        response = table.query(
            KeyConditionExpression=Key('username').eq(username)
        )
        items = response['Items']
        if len(items) > 0:
            return apology("Username already exists")
        table.put_item(
            Item={
                'username': username,
                'password': generate_password_hash(password)
            }
        )
        msg = "congrats"
        return render_template("login.html", msg=msg)
    except:
        return apology("Username already exists")



# Control the user is logged in
def is_logged_in(username,password):

    username = sanitize_login_input(username)
    try:
        result = table.query(
            KeyConditionExpression=Key('username').eq(username)
        )
        items = result['Items']
        name = items[0]['username']
        is_verified = check_password_hash(items[0]['password'], password)

        return is_verified
    except:
        return False



# Checking domain again attackers
def domainCheck(param):
    if re.match('^([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', param):        
        return param
    else:
        return False



# Make safe URL
def urlCheck(param):
    if re.match('^(http|https):\/\/[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$',param):
        return param
    else:
        return False



# Getting subdomains
def subdomains(domain):
    result = subprocess.check_output(['scripts/recon.sh', domain]).decode('utf-8')
    output = json.loads(result)
    return output



# Scanning IP's via Shodan
# def ipScan(subdomain):
#     domain = re.search("([a-zA-Z0-9-]+\.[a-zA-Z]{2,})(?:\/.*)?$",subdomain).group()
#     result = subprocess.check_output(['scripts/ipscan.sh', domain]).decode('utf-8')
#     output = json.loads(result)
#     return output



# Scannning domain 
def vulnscanner(domain):
    cmd = f"scripts/vulnscan.sh {domain}"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in iter(process.stdout.readline, b''):
         #line.rstrip() + b'<br/><\n'
         yield b'<div style="color:white">' + line + b'</div>'



# Scanning directories 
def dirscanner(domain):
    cmd = f"scripts/dirscan.sh {domain}"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in iter(process.stdout.readline, b''):
                 
        #line.rstrip() + b'<br/><\n'
        yield b'<div style="color:white">' + line + b'</div>'
        


# Scanning common ports of domain IP's
def ipscanner(domain):
    cmd = f"scripts/ipscan.sh {domain}"
    process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    for line in iter(process.stdout.readline, b''):
                 
        #line.rstrip() + b'<br/><\n'
        yield b'<div style="color:white">' + line + b'</div>'
