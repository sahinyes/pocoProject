import subprocess, json, pdb
from flask import Flask, redirect, make_response, jsonify, flash, render_template, request, session, Response, stream_with_context
# from flask_session import Session
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
from helpers import *
from werkzeug.security import check_password_hash, generate_password_hash
import config
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, set_access_cookies
from datetime import timedelta
# import ssl


# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
# context.load_cert_chain('cert.pem', 'key.pem')


# Configure applicaiton
app = Flask(__name__)

app.config.from_object(config)
app.secret_key = 'your-secret-key'

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
# app.config['SECRET_KEY'] = 'secret!'


# JWT

app.config["JWT_ALGORITHM"] = "HS256"
app.config["JWT_COOKIE_SECURE"] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config['JWT_COOKIE_CSRF_PROTECT'] = False

jwt = JWTManager(app)

# DB WILL COME HERE
dynamodb = boto3.resource('dynamodb', region_name='eu-central-2')
table = dynamodb.Table('bloguser')


# # Configure session to use filesystem (instead of signed cookies)
# app.config["SESSION_TYPE"] = "dynamodb"
# app.config["SESSION_PERMANENT"] = False
# app.config['SESSION_USE_SIGNER'] = True
# app.config['SESSION_DYNAMODB'] = boto3.resource('dynamodb').Table('bloguser')
# Session(app)


# @app.after_request
# def after_request(response):
#     """Ensure responses aren't cached"""
#     response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
#     response.headers["Expires"] = 0
#     response.headers["Pragma"] = "no-cache"
#     return response

@jwt.unauthorized_loader
def custom_unauthorized_response(_err):
    return redirect("/login")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET","POST"])
def register():
    
    #! Sanitize inputs here also for dynamodb

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        key = request.form.get("key")
        register_key = app.config["REGISTER_KEY"]

        
        # Checking input 

        if not username:
            return apology("Please enter a username")
        elif not password:
            return apology("Please enter a password")
        elif not confirm:
            return apology("Please enter both passwords")
        elif password != confirm:
            return apology("Passwords dosent match")
        elif key == register_key:
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
        else:
            return apology("Key does not match")
    
    elif request.method == "GET":
        return render_template("register.html")

    return render_template("register.html")


@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form['username']
        password = request.form['password']
        
        # table = dynamodb.Table('users')
        result = table.query(
            KeyConditionExpression=Key('username').eq(username)
        )
        items = result['Items']
        name = items[0]['username']

        is_verified = check_password_hash(items[0]['password'], password)
        if is_verified == True:

            access_token = create_access_token(identity=name)
            #session['access_token_cookie'] = access_token

            response = make_response(redirect('/dashboard'))

            #session['jwt_token'] = access_token
            set_access_cookies(response, access_token)

            return response
            
            #return render_template("/dashboard.html",name=name)
        else:
            return apology("Invalid username or password")
    return render_template("login.html")

                
        #! Sanitize inputs here also for dynamodb
        

@app.route("/dashboard", methods=["GET","POST"])
@jwt_required()

def dashboard():
    #  data = get_jwt_identity()

    # current_user = get_jwt_identity()
     return render_template("dashboard.html")


#! Dont forget 'crt.py = none' issue
@app.route("/recon",methods=["POST"])
@jwt_required()

def recon():

    if request.method == "POST":

        domain = request.form.get("domain")
        
        if domainCheck(domain) != False:

            try:
                domain = domainCheck(domain)
                output = subdomains(domain)
                return render_template("recon.html", output=output)
            except Exception as e:
                return apology("Invalid domain", 403)
        else:
            return apology("Invalid domain", 403)
        


@app.route("/scan",methods=["GET","POST"])
@jwt_required()
def scan():
       
       if request.method == "POST":        
           domain = request.form.get("value")
           
           try:
               urlCheck(domain)
           except:
               return apology("Invalid URL", 403)
           
           domain = urlCheck(domain)

       return render_template("scan.html",domain=domain)


@app.route('/vulnscan',methods=["GET"])
@jwt_required()
def vulnscan():
        
        if request.method == "GET":    
            domain = request.args.get('url')

            # Sanitizing URL
            if urlCheck(domain)!= False:
                
                try:               
                    domain = urlCheck(domain)
                    return Response(stream_with_context(vulnscanner(domain)))
                except:
                    # Something went wrong
                    return apology("Invalid URL", 403)
            else:
                # 403
                return apology("Invalid URL", 403)


@app.route('/dirscan',methods=["GET"])
@jwt_required()
def dirscan():
        
        if request.method == "GET":

            domain = request.args.get('url')

            # Sanitizing URL 
            if urlCheck(domain) != False:

                try:
                    domain = urlCheck(domain)
                    return Response(stream_with_context(dirscanner(domain)))    
                except Exception as e:
                    # Something went wrong
                    return apology("Invalid URL", 403)
            else:
                # 403
                return apology("Invalid URL", 403)

# if __name__ == '__main__':
#     app.run(ssl_context=context)