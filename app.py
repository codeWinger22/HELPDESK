from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response,session
import os
import json
import os
import datetime
from datetime import datetime
from flask_wtf.csrf import CSRFProtect

from urllib.parse import urlencode

import secrets
#for chat
from requests_oauthlib import OAuth2Session
from datetime import datetime, timedelta
from bson.json_util import dumps
from flask_socketio import SocketIO, join_room, leave_room
from jinja2 import environment
from pymongo.errors import DuplicateKeyError
from db import get_user, save_user, save_room, add_room_members, get_rooms_for_user, get_room, is_room_member, \
   get_room_members, is_room_admin, update_room, remove_room_members, save_message, get_messages,get_room_existence,add_room_member
from flask_cors import CORS, cross_origin


from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from init_db import initialize
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS, cross_origin
from user import User,UserManual,tokens
import subprocess
from flask_wtf import CSRFProtect
import sqlite3
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
app.config['PERMANENT_SESSION_LIFETIME'] = 86400

socketio = SocketIO(app)
app.config['SERVER_NAME'] = 'localhost:5000'
global oauth
oauth = OAuth(app)
login_manager = LoginManager()
login_manager.init_app(app)
global Userdata
Userdata = []
global usertoken 
usertoken = ""
global active_user
active_user = None
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
    #print(current_user)
    if(current_user.is_authenticated):
        print("from final ")
        print(current_user.name)
        print(current_user.email)
        
        return render_template("facebook.html")
        #return ("<h1> YOU ARE LOGGED IN </h1>"
         #       "<div> <p> Google Profile </p>"
          #      '<img src = "{}" alt = "Google Profile Pic" ></img></div>'
           #     '<a class "button" href = "/logout">Logout</a>'.format(current_user.name,current_user.email,current_user.profile_pic))
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
        ans = UserManual.getemail(email)
        print(ans)
        if(ans == None):
            msg = "No User Exists with this mail"
            return render_template("SignUp.html",msg = msg)
        
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
    user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)
    print(Userdata)
    print("Sing in")
    #user already present condition
    if( returnfunction != None and len(Userdata)>0):
        print("user already exists")
        userManualget = UserManual.get(unique_id)
        print(userManualget)
        if(userManualget != None ):
            if(user_email != Userdata[1]):
                msg = "Email Mismatch"
                Userdata.clear()
                return render_template("SignUp.html",msg = msg)
            else:
                msg = "User Already Exists Please Sign In"
                Userdata.clear()
                return render_template('SignIn.html',msg = msg)
        elif(userManualget == None):
            msg = "User Already Exists with SignIn Using Google"
            Userdata.clear()
            return render_template('SignIn.html',msg = msg)
      

    #when user is already signed in using gmail and tries to create new account ,redirect to login
    elif(returnfunction !=None and len(Userdata)<0):
        print("Sign in using google")
        
        #return render_template('SignIn.html')
    #when User is not present in any table
   
    elif(returnfunction == None and len(Userdata )>0):
        print(user_email)
        print(Userdata[1])
        if(user_email == Userdata[1]):
            user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)
            User.create(unique_id,username,user_email, picture)
            userM = UserManual(id = unique_id , name = Userdata[0], email=Userdata[1] , password= Userdata[2] )
            UserManual.create(user.id,Userdata[0],Userdata[1],Userdata[2])
            msg = "Successfully Register Please SignIn"
            Userdata.clear()
            return render_template('SignIn.html',msg = msg)
        else:
                #print(user.email)
                #print(Userdata[1])
                
            msg = "Email MisMatching"
            print("mail no matching")
            Userdata.clear()
            return render_template('SignUp.html',msg = msg)
   

    #start the session
      
    if(login_user(user)):
        print("user logged in")
    else:
        print("user not logged in")



    #and redirect to the homepage
    return redirect(url_for('index')) #def index which is created previously


@app.route('/facebook/')
def facebook():
    FACEBOOK_CLIENT_ID = "936489797983122"
    FACEBOOK_CLIENT_SECRET = "0f5365e775d2923b060a102cde21edc4"
    REDIRECT_URI = 'http://localhost:5000/facebook/auth'
    SCOPE = ['pages_show_list', 'pages_read_engagement', 'pages_manage_metadata', 'pages_read_user_content', 'pages_messaging']

# Facebook API endpoints
    AUTHORIZE_URL = 'https://www.facebook.com/v19.0/dialog/oauth'
    ACCESS_TOKEN_URL = 'https://graph.facebook.com/v19.0/oauth/access_token'
    GRAPH_API_URL = 'https://graph.facebook.com/v19.0'

# Webhook configuration
    WEBHOOK_VERIFY_TOKEN = 's'
    WEBHOOK_CALLBACK_URL = 'https://0293-49-36-33-80.ngrok-free.app/webhook'  # Adjust the callback URL as needed

    params = {
        'client_id': FACEBOOK_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': ','.join(SCOPE)
    }
    auth_url = f"{AUTHORIZE_URL}?{urlencode(params)}"
    return redirect(auth_url)

@app.route('/facebook/auth/')
def facebook_auth():
    FACEBOOK_CLIENT_ID = "936489797983122"
    FACEBOOK_CLIENT_SECRET = "0f5365e775d2923b060a102cde21edc4"
    REDIRECT_URI = 'http://localhost:5000/facebook/auth'
    SCOPE = ['pages_show_list','pages_messaging_subscriptions', 'pages_read_engagement', 'pages_manage_metadata', 'pages_read_user_content', 'pages_messaging']

# Facebook API endpoints
    AUTHORIZE_URL = 'https://www.facebook.com/v19.0/dialog/oauth'
    ACCESS_TOKEN_URL = 'https://graph.facebook.com/v19.0/oauth/access_token'
    GRAPH_API_URL = 'https://graph.facebook.com/v19.0'

# Webhook configuration
    WEBHOOK_VERIFY_TOKEN = 's'
    WEBHOOK_CALLBACK_URL = 'https://0293-49-36-33-80.ngrok-free.app/webhook'  # Adjust the callback URL as needed

    code = request.args.get('code')
    if code:
        params = {
            'client_id': FACEBOOK_CLIENT_ID,
            'client_secret': FACEBOOK_CLIENT_SECRET,
            'redirect_uri': REDIRECT_URI,
            'code': code
        }
        response = requests.get(ACCESS_TOKEN_URL, params=params)
        if response.status_code == 200:
            data = response.json()
            access_token = data['access_token']
            
            session['access_token'] = access_token
            active_user = access_token
            print("this is active user")
            print(active_user)
           
            
            # Get the Page Access Token with required permissions
            page_access_token = get_page_access_token(access_token)
            
            session["page"] = page_access_token[0]
            session["pageid"] =page_access_token[1]
            perman = get_long_lived_token(access_token,page_access_token[1])
            search = tokens.gettoken(1)
            if(search != None):
                tokens.update(1,perman)
            else:
                tokens.create(1,perman)
            session["perman"] = perman
            if page_access_token:
                # Subscribe to webhook events using the Page Access Token
                subscribe_to_webhook(page_access_token[0],page_access_token[1])
                check_permissions(page_access_token[0],page_access_token[1])
                return redirect(url_for('pages'))
            else:
                return 'Failed to retrieve Page Access Token'
        else:
            return 'Failed to retrieve access token'
    else:
        return 'Authorization failed'


def check_permissions(page_access_token, page_id):
    FACEBOOK_CLIENT_ID = "936489797983122"
    FACEBOOK_CLIENT_SECRET = "0f5365e775d2923b060a102cde21edc4"
    api_endpoint = "https://graph.facebook.com/debug_token"
    params = {
        'input_token': page_access_token,
        'access_token': f"{FACEBOOK_CLIENT_ID}|{FACEBOOK_CLIENT_SECRET}"
    }
    response = requests.get(api_endpoint, params=params)
    if response.status_code == 200:
        data = response.json()
        if 'data' in data and 'scopes' in data['data']:
            permissions = data['data']['scopes']
            print(permissions)
            return permissions
        else:
            print("Permissions not found in response.")
            return None
    else:
        print("Failed to retrieve permissions. Status code:", response.status_code)
        print("Response:", response.json())
        return None

@app.route('/pages')
def pages():
    GRAPH_API_URL = 'https://graph.facebook.com/v19.0'
    access_token = session.get('access_token')
    
    if access_token:
        response = requests.get(f"{GRAPH_API_URL}/me/accounts", params={'access_token': access_token})
        
        if response.status_code == 200:
            pages_data = response.json()
            return str(pages_data)  # Return information about Facebook pages
        else:
            return 'Failed to fetch pages'
    else:
        return redirect(url_for('facebook'))  # 

def get_page_access_token(user_access_token):
    FACEBOOK_CLIENT_ID = "936489797983122"
    FACEBOOK_CLIENT_SECRET = "0f5365e775d2923b060a102cde21edc4"
    REDIRECT_URI = 'http://localhost:5000/facebook/auth'
    SCOPE = ['pages_show_list', 'pages_read_engagement', 'pages_manage_metadata', 'pages_read_user_content', 'pages_messaging']

# Facebook API endpoints
    AUTHORIZE_URL = 'https://www.facebook.com/v19.0/dialog/oauth'
    ACCESS_TOKEN_URL = 'https://graph.facebook.com/v19.0/oauth/access_token'
    GRAPH_API_URL = 'https://graph.facebook.com/v19.0'

# Webhook configuration
    WEBHOOK_VERIFY_TOKEN = 's'
    WEBHOOK_CALLBACK_URL = 'https://0293-49-36-33-80.ngrok-free.app/webhook'  # Adjust the callback URL as needed

    response = requests.get(f"{GRAPH_API_URL}/me/accounts", params={'access_token': user_access_token})
    if response.status_code == 200:
        pages_data = response.json()
        print("pages data")
        print(pages_data)
        print()
        # Assuming the user has only one page associated with the app
        if 'data' in pages_data and len(pages_data['data']) > 0:
            
            d = []
            d.append(pages_data['data'][0]['access_token'] )
            d.append( pages_data['data'][0]['id'])
            
            return d  # Return the access token of the first page
    return None


def get_long_lived_token(short_lived_token,page_id):
    FACEBOOK_CLIENT_ID = "936489797983122"
    FACEBOOK_CLIENT_SECRET = "0f5365e775d2923b060a102cde21edc4"
    url = 'https://graph.facebook.com/v19.0/oauth/access_token'
    params = {
        'grant_type': 'fb_exchange_token',
        'client_id': '936489797983122',
        'client_secret': '0f5365e775d2923b060a102cde21edc4',
        'fb_exchange_token': short_lived_token
    }
    response = requests.get(url, params=params)
    data = response.json()
    if 'access_token' in data:
        long_lived_token = data['access_token']
        long_lived_page_access = get_long_lived_page_access_token(long_lived_token,page_id)
        return long_lived_page_access
    else:
        return None


def get_long_lived_page_access_token(long_lived_user_token, page_id):
    """Exchange a long-lived User Access Token for a long-lived Page Access Token."""
    url = f'https://graph.facebook.com/{page_id}?fields=access_token'
    params = {'access_token': long_lived_user_token}
    response = requests.get(url, params=params)
    data = response.json()
    if 'access_token' in data:
        return data['access_token']
    else:
        return None

def subscribe_to_webhook( page_access_token,page_id):
    session["page_access_token"] = page_access_token
    session["page_id"] = page_id
    curl_command = f'curl -i -X POST "https://graph.facebook.com/{page_id}/subscribed_apps" ' \
                   f'-d "subscribed_fields=feed,messages" ' \
                   f'-d "access_token={page_access_token}"'
    
    # Execute the curl command
    try:
        process = subprocess.Popen(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        if process.returncode == 0:
            print("Webhook subscription successful.")
        else:
            print(f"Failed to subscribe to webhook events: {error.decode()}")
    except Exception as e:
        print(f"Error: {e}")






# def subscribe_to_webhook( page_access_token,page_id):
    
#    # Define the curl command with double quotes around the URL
#     curl_command = f'curl -i -X POST "https://graph.facebook.com/{page_id}/subscribed_apps" ' \
#                    f'-d "subscribed_fields=feed" ' \
#                    f'-d "access_token={page_access_token}"'
    
#     # Execute the curl command
#     try:
#         process = subprocess.Popen(curl_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#         output, error = process.communicate()
#         if process.returncode == 0:
#             print("Webhook subscription successful.")
#         else:
#             print(f"Failed to subscribe to webhook events: {error.decode()}")
#     except Exception as e:
#         print(f"Error: {e}")
        
# @app.route('/facebook/')
# def facebook():
   
#     # Facebook Oauth Config
#     FACEBOOK_CLIENT_ID = "936489797983122"
#     FACEBOOK_CLIENT_SECRET = "0f5365e775d2923b060a102cde21edc4"
#     REDIRECT_URI = 'http://localhost:5000/facebook/auth'  # Adjust the redirect URI as needed
#     SCOPE = ['pages_show_list', 'pages_read_engagement', 'pages_manage_metadata','pages_read_user_content', 'pages_messaging']
#   # Specify the required permissions

# # Facebook API endpoints
#     AUTHORIZE_URL = 'https://www.facebook.com/v12.0/dialog/oauth'
#     ACCESS_TOKEN_URL = 'https://graph.facebook.com/v12.0/oauth/access_token'
#     GRAPH_API_URL = 'https://graph.facebook.com/v12.0'

#     params = {
#         'client_id': FACEBOOK_CLIENT_ID,
#         'redirect_uri': REDIRECT_URI,
#         'scope': ','.join(SCOPE)
#     }
#     auth_url = f"{AUTHORIZE_URL}?{urlencode(params)}"
#     return redirect(auth_url)


# @app.route('/facebook/auth/')
# def facebook_auth():
#     FACEBOOK_CLIENT_ID = "936489797983122"
#     FACEBOOK_CLIENT_SECRET = "0f5365e775d2923b060a102cde21edc4"
#     REDIRECT_URI = 'http://localhost:5000/facebook/auth'  # Adjust the redirect URI as needed
#     SCOPE = ['pages_show_list', 'pages_read_engagement']  # Specify the required permissions

#     ACCESS_TOKEN_URL = 'https://graph.facebook.com/v12.0/oauth/access_token'
#     GRAPH_API_URL = 'https://graph.facebook.com/v12.0'
#     code = request.args.get('code')
#     if code:
#         params = {
#             'client_id': FACEBOOK_CLIENT_ID,
#             'client_secret': FACEBOOK_CLIENT_SECRET,
#             'redirect_uri': REDIRECT_URI,
#             'code': code
#         }
#         response = requests.get(ACCESS_TOKEN_URL, params=params)
#         if response.status_code == 200:
#             data = response.json()
#             access_token = data['access_token']
#             session['access_token'] = access_token
            
#             return redirect(url_for('pages'))
#         else:
#             return 'Failed to retrieve access token'
#     else:
#         return 'Authorization failed'

# @app.route('/pages')
# def pages():
#     GRAPH_API_URL = 'https://graph.facebook.com/v12.0'
#     access_token = session.get('access_token')
#     if access_token:
#         response = requests.get(f"{GRAPH_API_URL}/me/accounts", params={'access_token': access_token})
#         if response.status_code == 200:
#             pages_data = response.json()
#             return str(pages_data)
#         else:
#             return 'Failed to fetch pages'




# @app.route('/facebook/')
# def facebook():
   
#     # Facebook Oauth Config
#     FACEBOOK_CLIENT_ID = "936489797983122"
#     FACEBOOK_CLIENT_SECRET = "0f5365e775d2923b060a102cde21edc4"
#     oauth.register(
#          name='facebook',
#     client_id=FACEBOOK_CLIENT_ID,
#     client_secret=FACEBOOK_CLIENT_SECRET,
#     access_token_url='https://graph.facebook.com/oauth/access_token',
#     access_token_params={'scope': 'email,manage_pages,pages_show_list,pages_manage_metadata,pages_messaging,pages_read_engagement,read_page_mailboxes'},
#     request_token_params=None,
#     authorize_url='https://www.facebook.com/dialog/oauth',
#     authorize_params=None,
#     api_base_url='https://graph.facebook.com/',
#     client_kwargs={'scope': 'email'},
#     )
#     redirect_uri = url_for('facebook_auth', _external=True)
#     return oauth.facebook.authorize_redirect(redirect_uri)


# @app.route('/facebook/auth/')
# def facebook_auth():
#     token = oauth.facebook.authorize_access_token()
#     print(type(token))
#     print(token)
    
#     resp = oauth.facebook.get('https://graph.facebook.com/me/accounts')

#     pages = resp.json()
#     print(pages)
    
#     print("pages list")
   
#     pages = resp.json()['data'] if 'data' in resp.json() else []
#     print(pages)
#     resp = oauth.facebook.get('me/accounts', token=token)
#     pages = resp.json()['data'] if 'data' in resp.json() else []

#     # Extracting page tokens
#     page_tokens = [page['access_token'] for page in pages]
#     print("printing page tokens")
#     print(page_tokens)
#     tokens = token['access_token']
#     content = {'name':"Gouri" , 'tokens':"avf"}  #dummy
#     return render_template("facebookintro.html",content = content)


# Updated scope with additional permissions



@app.route('/deleteIntegration<variable>')
def deleteIntegration(variable):

    user_access_token = variable
    print("printing token")
    print(usertoken)
    # Call a function to revoke the Facebook OAuth token
    if revoke_facebook_token(user_access_token):
        # Perform any necessary cleanup, such as removing the user's Facebook ID from your database
        # Redirect to a success page or reload the current page
        return render_template("facebook.html")
    else:
    
        return render_template("facebook.html")


def revoke_facebook_token(user_access_token):
    # Facebook Graph API endpoint for revoking tokens
    graph_api_url = f"https://graph.facebook.com/v12.0/me/permissions"
    print(user_access_token)
    print("above")
    # Parameters to include in the request
    params = {
        "access_token": user_access_token
    }

    try:
        # Send a DELETE request to revoke the token
        response = requests.delete(graph_api_url, params=params)
        response.raise_for_status()  
        print("deleted successfully")
        # Raise an exception for HTTP errors
        return True  # Token revoked successfully
    except requests.exceptions.RequestException as e:
        print("Error revoking token:", e)
        return False  # Failed to revoke token
    












def get_google_provider_cfg():
 
    return requests.get(GOOGLE_DISCOVERY_URL).json()




# @app.route('/webhook', methods=['GET', 'POST'])
# def webhook():
#     if request.method == 'GET':
#         verify_token = request.args.get('hub.verify_token')
#         challenge = request.args.get('hub.challenge')
#         if verify_token == None:  # Replace 'YOUR_VERIFY_TOKEN' with your actual verify token
#             return challenge, 200
#         else:
#             return 'Invalid verify token', 403
#     elif request.method == 'POST':
#         data = request.json
#         if data.get('object') == 'page':
#             for entry in data.get('entry', []):
#                 for messaging_event in entry.get('messaging', []):
#                     # Extract the message text
#                     if 'message' in messaging_event:
#                         sender_id = messaging_event['sender']['id']
#                         message_text = messaging_event['message']['text']
#                         # Handle the message here (e.g., save it to a database, process it, etc.)
#                         print(f"Received message from {sender_id}: {message_text}")
#         return jsonify({'status': 'success'})



# @app.route('/webhook', methods=['GET', 'POST'])
# def webhook():
#     if request.method == 'GET':
#         verify_token = request.args.get('hub.verify_token')
#         print(verify_token)
#         challenge = request.args.get('hub.challenge')
#         if verify_token == 'm':  # Replace with your verify token
#             print(challenge)
#             #for first time 
#             return challenge , 200
#             return "done", 200
#         else:
#             return 'Invalid verify token', 403
#     elif request.method == 'POST':
#         # Handle incoming events
#         return 'OK', 200


@app.route('/webhook',methods=['GET', 'POST'])
def webhook():
    
    if request.method == 'GET':
        verify_token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        if verify_token == 's':  # Replace with your verify token
            return challenge
            #return render_template("main.html")
        else:
            return 'Invalid verify token', 403
    elif request.method == 'POST':
        print("reached post")
        verify_token = request.args.get('hub.verify_token')
        if(verify_token == None):
            print("YESSSSSSSSSSS")
        # Handle incoming events
        data = request.json
        # Process the incoming data
        process_webhook_data(data)
        # Respond with a success message
        return 'OK', 200

def process_webhook_data(data):
    # Here you can handle the incoming webhook data
    # Extract relevant information from the data and perform necessary actions
    print("Received webhook data:", data)
    
    # Extract recipient ID and page ID from the response
    recipient_id = data['entry'][0]['messaging'][0]['sender']['id']
    page_id = data['entry'][0]['messaging'][0]['recipient']['id']
    
    # Example: Extract message text from data and process it
    if 'entry' in data and len(data['entry']) > 0:
        for entry in data['entry']:
            if 'messaging' in entry:
                for message in entry['messaging']:
                    if 'message' in message and 'text' in message['message']:
                        message_text = message['message']['text']
                        print("Received message:", message_text)
                        
                        # Send a reply message using the send_message function
                        page_access_token = session.get("page")  # Replace with your actual Page Access Token
                        send_message( page_id,page_access_token, recipient_id, "ssss")



def refresh_user_access_token( ):
    short_lived_token =active_user
    print(short_lived_token)
    FACEBOOK_CLIENT_ID = "936489797983122"
    FACEBOOK_CLIENT_SECRET = "0f5365e775d2923b060a102cde21edc4"
    url = 'https://graph.facebook.com/v12.0/oauth/access_token'
    params = {
        'grant_type': 'fb_exchange_token',
        'client_id': FACEBOOK_CLIENT_ID,
        'client_secret': FACEBOOK_CLIENT_SECRET,
        'fb_exchange_token': short_lived_token
    }
    response = requests.get(url, params=params)
    data = response.json()
    if 'access_token' in data:
        return data['access_token']
    else:
        return None


def send_message(pageid,page_access_token, recipient_id, message_text):
    
    
    access_token_user = refresh_user_access_token()
    pagess = get_page_access_token(access_token_user)
    page_final = tokens.gettoken(1)
    page_final1  = page_final.activetoken

    url = "https://graph.facebook.com/v19.0/me/messages"
    params = {
    "recipient": {"id": recipient_id},
    "messaging_type": "RESPONSE",
    "message": {"text": "HELLO"},
    "access_token": page_final1}
    response = requests.post(url, json=params)
    
    if response.status_code == 200:
        print("Message sent successfully.")
    else:
        print(f"Failed to send message. Status code: {response.status_code}")
        print(response.text)


@app.route("/common")
def common():
    return render_template("common.html")



#socket io



@socketio.on('send_message')
def handle_send_message_event(data):
    app.logger.info("{} has sent message to the room {}: {}".format(data['username'],
                                                                    data['room'],
                                                                    data['message']))
    data['created_at'] = datetime.now().strftime("%d %b, %H:%M")
    save_message(data['room'], data['message'], data['username'])
    socketio.emit('receive_message', data, room=data['room'])






@app.after_request
def after_request_func(response):
    origin = request.headers.get('Origin')
    if request.method =='OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Credentials','true')
        response.headers.add('Access-Control-Allow-Headers','Content-Type')
        response.headers.add('Access-Control-Allow-Headers','x-csrf-token')
        response.headers.add('Access_Control-Allow-Methods','GET,POST,OPTIONS,PUT,PATCH.DELETE')
        if origin:
            response.headers.add('Access-Control-Allow-Origin',origin)
    else:
        response.headers.add('Access-Control-Allow-Credentials','true')
        if origin:
            response.headers.add('Access-Control-Allow-Origin',origin)
    return response



@socketio.on('join_room')
def handle_join_room_event(data):
    app.logger.info("{} has joined the room {}".format(data['username'], data['room']))
    join_room(data['room'])
    socketio.emit('join_room_announcement', data, room=data['room'])


@socketio.on('leave_room')
def handle_leave_room_event(data):
    app.logger.info("{} has left the room {}".format(data['username'], data['room']))
    leave_room(data['room'])
    socketio.emit('leave_room_announcement', data, room=data['room'])



if __name__ == '__main__':
    app.run(debug = True)