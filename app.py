import subprocess, json, pdb
from flask import Flask, redirect, jsonify, flash, render_template, request, session, Response, stream_with_context
from flask_session import Session
import boto3
from botocore.exceptions import ClientError
from helpers import *
from werkzeug.security import check_password_hash, generate_password_hash
# Configure applicaiton
app = Flask(__name__)

#! TAKE CONFIGS FROM CLI

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
# app.config['SECRET_KEY'] = 'secret!'

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

# DB WILL COME HERE
dynamodb = boto3.resource('dynamodb', region_name='eu-central-2')
table = dynamodb.Table('users')

# @app.after_request
# def after_request(response):
#     """Ensure responses aren't cached"""
#     response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
#     response.headers["Expires"] = 0
#     response.headers["Pragma"] = "no-cache"
#     return response


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/project", methods=["GET"])
def project():
    return render_template("project.html")


@app.route("/register", methods=["GET","POST"])
def register():
    
    #! Sanitize inputs here also for dynamodb

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        
        # Checking input 

        if not username:
            return apology("Please enter a username")
        elif not password:
            return apology("Please enter a password")
        elif not confirm:
            return apology("Please enter both passwords")
        elif password != confirm:
            return apology("Passwords dosent match")
        elif password == confirm:
            try:
                # table = dynamodb.Table('users')
                table.put_item(
                    Item={
                        'username': {'S': username},
                        'password': {'S': password}
                    }
                    )
                msg = "congrats"
                return render_template("login.html", msg=msg)
            except:
                return apology("Username already exists")
        else:
            return apology("Passwords dosent match")
    
    elif request.method == "GET":
        return render_template("project.html")

    return render_template("project.html")


@app.route("/login", methods=["GET","POST"])
def login():


    if request.method == "POST":

        username = request.form['username']
        password = request.form['password']
        
        # table = dynamodb.Table('users')
        response = table.query(
                KeyConditionExpression=Key('email').eq(username)
        )
        items = response['Items']
        name = items[0]['name']
        print(items[0]['password'])
        if password == items[0]['password']:
            
            return render_template("dashboard.html")
    return render_template("login.html")

                


        #! Sanitize inputs here also for dynamodb
        



@app.route("/dashboard", methods=["GET","POST"])
def dashboard():
    return render_template("dashboard.html")


#! Dont forget 'crt.py = none' issue
@app.route("/recon",methods=["GET","POST"])
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
