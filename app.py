from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response,session
import os
import json
import os
import datetime
from datetime import datetime




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
from user import User,UserManual
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
    user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)

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

@app.route('/facebook/')
def facebook():
   
    # Facebook Oauth Config
    FACEBOOK_CLIENT_ID = "7879950605366790"
    FACEBOOK_CLIENT_SECRET = "d998cd124468b325cf1d9badb4f06997"
    oauth.register(
        name='facebook',
        client_id=FACEBOOK_CLIENT_ID,
        client_secret=FACEBOOK_CLIENT_SECRET,
        access_token_url='https://graph.facebook.com/oauth/access_token',
        access_token_params=None,
        request_token_params={'scope': 'email,manage_pages,pages_show_list,pages_manage_metadata,pages_messaging,pages_read_engagement'},

        authorize_url='https://www.facebook.com/dialog/oauth',
        authorize_params=None,
        api_base_url='https://graph.facebook.com/',
        client_kwargs={'scope': 'email'},
    )
    redirect_uri = url_for('facebook_auth', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)
 
@app.route('/facebook/auth/')
def facebook_auth():
    token = oauth.facebook.authorize_access_token()
    
    usertoken = token['access_token']
    print(usertoken)
    print(type(usertoken))
    resp = oauth.facebook.get(
        'https://graph.facebook.com/me?fields=id,name,email,picture{url}')
    profile = resp.json()
    print(profile['name'])
    name = profile['name']
    print("Facebook User ", profile)
    tokens  = usertoken
    content = {'name':name,
             "tokens":tokens}
    content = {'name':name , 'tokens':tokens}
    return render_template("facebookintro.html",content = content)
 




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


def fetch_messages(page_access_token):
    # Make a GET request to fetch messages
    graph_api_url = f"https://graph.facebook.com/v13.0/me/conversations?access_token={page_access_token}"
    response = OAuth2Session().get(graph_api_url)
    if response.status_code == 200:
        return response.json()
    else:
        return None



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
    


# 



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


@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        verify_token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        if verify_token == None:  # Replace with your verify token
            return render_template("main.html")
        else:
            return 'Invalid verify token', 403
    elif request.method == 'POST':
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
    # Example: Extract message text from data and process it
    if 'entry' in data and len(data['entry']) > 0:
        for entry in data['entry']:
            if 'messaging' in entry:
                for message in entry['messaging']:
                    if 'message' in message and 'text' in message['message']:
                        message_text = message['message']['text']
                        print("Received message:", message_text)
                        # Process the message further (e.g., send a response)
                        # Your code to handle the message text goes here


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