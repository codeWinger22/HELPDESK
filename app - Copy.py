from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response,session
import os
import json
import os
import re
import sqlite3
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from init_db import initialize

from flask_cors import CORS, cross_origin
from user import User,UserManual
import sqlite3
from flask import Flask, render_template, url_for, redirect
from authlib.integrations.flask_client import OAuth
import os
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user)
from oauthlib.oauth2 import WebApplicationClient
#WebapplicationClient because we are building it on the client side
import requests
from flask_cors import CORS, cross_origin

# set up the environment variable
# this environment variable need to be set in order to run it over http
# as we are running this currently on localhost
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # without https

# now we will import the environment variables
#GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID',None)
#GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET',None)
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_CLIENT_ID = "468719197376-6109mvco7ncjaneqq0vi2f4ig7mm5ujs.apps.googleusercontent.com"
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")






app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
login_manager = LoginManager()
login_manager.init_app(app)
global Userdata
Userdata = []

# initialize a handler
@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content", 403

client = WebApplicationClient(GOOGLE_CLIENT_ID)

# initialize helper
@login_manager.user_loader
def load_user(user_id):
    flag = 0
    user = User.get(user_id)
    print(user, "from main helper")
    if not user:
        return None
    return user










@app.route('/')
def index():
   

    initialize()
    print("reached in index api")
    print(current_user)
    if(current_user.is_authenticated):
        print("from final ")
        print(current_user.name)
        print(current_user.email)
        return ("<h1> YOU ARE LOGGED IN </h1>"
                "<div> <p> Google Profile </p>"
                '<img src = "{}" alt = "Google Profile Pic" ></img></div>'
                '<a class "button" href = "/logout">Logout</a>'.format(current_user.name,current_user.email,current_user.profile_pic))
    else:
        print("not authenticated")
        #return render_template('index.html')
        return render_template('SignUp.html')

@app.route("/getRegisterData",methods=['POST'])
def getRegisterData():
    data = request.form
    name = data['username']
    email = data['email']
    password = data['psw']
    Userdata.clear()
    Userdata.append(name)
    Userdata.append(email)
    Userdata.append(password)
    return redirect( url_for('login'))
    
@app.route("/logoutwithout")
def logoutwithout():
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    if (logout_user()):
        print("logged out")
        current_user.authenticated = False


    return redirect(url_for('index'))


@app.route("/SignIn",methods=['GET', 'POST'])
def SignIn():
    if request.method == 'POST':
        data = request.form
        email = data['email']
        password = data['psw']
        ans = UserManual.get(email)
        if(ans == None):
            msg = "No User Exists with this mail"
            return render_template("SignIn.html",msg = msg)
        else:
            if(ans.email == email and ans.password == password ):
             #start the session
                result = User.getData(ans.email)
                user = User(id= result.id,name = result.name, email = result.email,profile_pic=result.profile_pic)

                if(login_user(user)):
                    print("user logged in")
                else:
                    print("user not logged in")
             #and redirect to the homepage
                return redirect(url_for('index')) #def index which is created previously
            else:
                msg = "Invalid Credentials"
                return render_template("SignIn.html",msg = msg)
    msg = ""
    return render_template("SignIn.html", msg = msg)
    
   


   

@app.route('/login')
def login():   
    google_provider_cgf =  get_google_provider_cfg()
    authorization_endpoint = google_provider_cgf['authorization_endpoint']
    request_uri  = client.prepare_request_uri(authorization_endpoint,redirect_uri="http://localhost:5000/login/callback",scope = ['openid','email','profile'])
    print("completed login process",request_uri)
    
    return redirect(request_uri)




@app.route('/login/callback')
def callback():
    
    client = WebApplicationClient(GOOGLE_CLIENT_ID)
    code = request.args.get('code')
    #authorization code 
    #now with this we can get the authorization
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint  = google_provider_cfg['token_endpoint']

    #prepare token url 
    token_url , headers , body = client.prepare_token_request(token_endpoint,authorization_response=request.url,redirect_url="http://localhost:5000/login/callback",code = code)
    token_response = requests.post(token_url,headers=headers,data = body,auth=(GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET))
    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg['userinfo_endpoint']
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri,headers=headers,data = body)
    print(userinfo_response.json())
    if(userinfo_response.json().get('email_verified')):
        unique_id = userinfo_response.json()['sub']
        user_email = userinfo_response.json()['email']
        picture = userinfo_response.json()['picture']
        username = userinfo_response.json()['given_name']
        print("before inserting into db callback function")
    else:
        return "User email not available or not verified by google",400
    #now we need to insert this user inside our sqlite db

   # user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)
    print(unique_id)
    returnfunction = User.get(unique_id)
    print(returnfunction)
    #Assuming that this is direct sign in with google
    if( returnfunction != None and len(Userdata)>0):
        print("user already exists")
        msg = " Auth User Already Exists with SignIn Using Google"
        return render_template('SignIn.html',msg = msg)
    #when user is already signed in using gmail and tries to create new account ,redirect to login
    elif(returnfunction !=None and len(Userdata)==0):
        print("Sign in using google")
        #return render_template('SignIn.html')
    #when User is not present in any table
    elif(returnfunction == None and len(Userdata )>0):
        print(user_email)
        print(Userdata[1])
        if(user_email == Userdata[1]):
            user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)
            User.create(unique_id,username,user_email, picture)
            UserManual.create(user.id,Userdata[0],Userdata[1],Userdata[2])
            msg = "Successfully Register Please SignIn"
            return render_template('SignIn.html',msg = msg)
        else:
                #print(user.email)
                #print(Userdata[1])
                
            msg = "Email MisMatching"
            print("mail no matching")
            
            return render_template('SignUp.html',msg = msg)
    else:
        user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)
        User.create(unique_id,username,user_email, picture)


    #start the session
      
    if(login_user(user)):
        print("user logged in")
    else:
        print("user not logged in")



    #and redirect to the homepage
    return redirect(url_for('index')) #def index which is created previously

def get_google_provider_cfg():
 
    return requests.get(GOOGLE_DISCOVERY_URL).json()






if __name__ == '__main__':
    app.run(debug = True)