import sqlite3

def initialize():

#conn.execute('CREATE TABLE if not exists user (name TEXT, addr TEXT, city TEXT, zip TEXT)')
    try:
        conn = sqlite3.connect('database.db')
        print("Connected to database successfully")
    except:
        print("db already created")

    try:
        conn.execute('CREATE TABLE if not exists user(id TEXT PRIMARY KEY ,name TEXT NOT NULL ,email TEXT UNIQUE NOT NULL,profile_pic TEXT NOT NULL)')
        print("Created table successfully!")
    except Exception as e:
        print(e)
    
    try:
        conn.execute('CREATE TABLE if not exists userManual(id TEXT PRIMARY KEY ,name TEXT NOT NULL ,email TEXT  UNIQUE NOT NULL,password TEXT NOT NULL)')
        print("Created table successfully!")
    except Exception as e:
        print(e)

    try:
        conn.execute('CREATE TABLE if not exists tokens(id TEXT PRIMARY KEY , activetoken TEXT NOT NULL)')
        print("Created table successfully!")
    except Exception as e:
        print(e)
    
    try:
        conn.execute('CREATE TABLE if not exists conversation(id TEXT PRIMARY KEY , page TEXT NOT NULL,sender TEXT NOT NULL)')
        print("Created table successfully!")
    except Exception as e:
        print(e)

  
    