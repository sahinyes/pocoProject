import os, secrets
from flask import Flask, redirect, make_response, render_template, request, Response, stream_with_context, flash
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
from helpers import *
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, set_access_cookies
from datetime import timedelta



# Configure applicaiton
app = Flask(__name__)
secret_key = secrets.token_hex(18)
app.secret_key = secret_key
register_key = os.environ.get('REGISTER_KEY')

#! Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
        


# JWT Configurations
app.config["JWT_ALGORITHM"] = "HS256"
app.config["JWT_COOKIE_SECURE"] = False
app.config['JWT_SECRET_KEY'] = 'your-secret-key'
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
jwt = JWTManager(app)



# DynamoDB Configurations
dynamodb = boto3.resource('dynamodb', region_name='eu-central-2')
table = dynamodb.Table('bloguser')



# Redirect if visitor not logged in
@jwt.unauthorized_loader
def custom_unauthorized_response(_err):
    return redirect("/login")



@app.route("/")
def index():
    return render_template("index.html")



@app.route("/register", methods=["GET","POST"])
def register():   

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        rkey = request.form.get("key")
        
        # Checking input 
        if not username:
            return apology("Please enter a username")
        elif not password:
            return apology("Please enter a password")
        elif not confirm:
            return apology("Please enter both passwords")
        elif password != confirm:
            return apology("Passwords dosent match")
        elif rkey == register_key:
            return register_user(username,password)
        else:
            return apology("Key does not match")
        
    elif request.method == "GET":
        return render_template("register.html")



@app.route("/login", methods=["GET","POST"])
def login():

    if request.method == "POST":

        username = request.form['username']
        password = request.form['password']
        
        if not username:
            flash("Please enter a username")
        elif not password:
            flash("Please enter a password")
        elif is_logged_in(username,password) == True:
            username = sanitize_login_input(username)

            try:
                access_token = create_access_token(identity=username)
                response = make_response(redirect('/dashboard'))
                set_access_cookies(response, access_token)
                return response
            
            except:
                return flash("Invalid username or password")
            
        else:
            flash("Invalid username or password")

    return render_template("login.html")



@app.route("/dashboard", methods=["GET","POST"])
@jwt_required()
def dashboard():
    return render_template("dashboard.html")



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
            except:
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
                # urlCheck doesn't allow
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
                # It doesn't allow
                return apology("Invalid URL", 403)



@app.route('/ipscan',methods=["GET"])
@jwt_required()
def ipscan():
        
        if request.method == "GET":

            domain = request.args.get('url')

            # Sanitizing URL 
            if urlCheck(domain) != False:

                try:
                    domain = urlCheck(domain)
                    return Response(stream_with_context(ipscanner(domain)))    
                except Exception as e:
                    # Something went wrong
                    return apology("Invalid URL", 403)
                
            else:
                # It doesn't allow
                return apology("Invalid URL", 403)