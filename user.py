

import sqlite3



from flask_login import UserMixin
class User(UserMixin):
    def __init__(self,id,name,email,profile_pic):
        self.id = id
        self.name = name
        self.email = email
        self.profile_pic = profile_pic
        
    
    @staticmethod
    def get(user_id):
      
        print(type(user_id))
        print(user_id)
        user = None
        try:
            con = sqlite3.connect("database.db")
           
        
        except:
            print("problem in connecting to database")
       

        try:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute('SELECT * FROM user WHERE id = ? ', (user_id, ))
            rows = cur.fetchone()
            if not rows:
                return None
            else:
                user = User(id = rows[0],name = rows[1],email = rows[2],profile_pic=rows[3])
                print("this is user from get method ",user)

        except Exception as e:
            print(e)
        finally:
            con.close()
        
        return user
        
    
    @staticmethod
    def getData(email):
      
        print(type(email))
        print(email)
        user = None
        try:
            con = sqlite3.connect("database.db")
           
        
        except:
            print("problem in connecting to database")
       

        try:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute('SELECT * FROM user WHERE email = ? ', (email, ))
            rows = cur.fetchone()
            if not rows:
                return None
            else:
                user = User(id = rows[0],name = rows[1],email = rows[2],profile_pic=rows[3])
                print("this is user from get method ",user)

            


        #user = db.execute("SELECT * FROM user").fetchall()
         
           
        except Exception as e:
            print(e)
        finally:
            con.close()
        
        return user
  
        #user = db.execute("SELECT * FROM user WHERE id = ?",(user_id,)).fetchone()
        #if not user:
         #   return None
        #user = User(id = user[0], name = User[1], email = User[2] , profile_pic= User[3])
        #return user

    @staticmethod
    def create(userid_,name, email, profile_pic):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in user create function")
        try:
            cur.execute("INSERT INTO user (id, name, email, profile_pic) VALUES (?,?,?,?)",(userid_, name, email, profile_pic))
            con.commit()
            print("Record successfully added to database")
          

        except Exception as e:
            con.rollback()
            print("Error in the INSERT")
            print(e)



        finally:
            con.close()

   


class UserManual:
    def __init__(self,id,name,email,password):
        self.id = id
        self.name = name
        self.email = email
        self.password = password
    

     
    @staticmethod
    def getemail(email):
      
        print(type(email))
        print(email)
        user = None
        try:
            con = sqlite3.connect("database.db")
           
        
        except:
            print("problem in connecting to database")
       

        try:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute('SELECT * FROM userManual WHERE email = ? ', (email, ))
            rows = cur.fetchone()
            if not rows:
                return None
            else:
                user = UserManual(id = rows[0],name = rows[1],email = rows[2],password=rows[3])
                print("this is user from get method ",user)
                


        

            


        #user = db.execute("SELECT * FROM user").fetchall()
         
           
        except Exception as e:
            print(e)
        finally:
            con.close()
        
        return user
  


       
    @staticmethod
    def get(userid):
      
        print(type(userid))
        print(userid)
        user = None
        try:
            con = sqlite3.connect("database.db")
           
        
        except:
            print("problem in connecting to database")
       

        try:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute('SELECT * FROM userManual WHERE id = ? ', (userid, ))
            rows = cur.fetchone()
            if not rows:
                return None
            else:
                user = UserManual(id = rows[0],name = rows[1],email = rows[2],password=rows[3])
                print("this is user from get method ",user)
                


        

            


        #user = db.execute("SELECT * FROM user").fetchall()
         
           
        except Exception as e:
            print(e)
        finally:
            con.close()
        
        return user
  
    
    @staticmethod
    def create(userid_,name, email, password):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in user create function")
        try:
            cur.execute("INSERT INTO userManual(id,name, email, password) VALUES (?,?,?,?)",(userid_,name, email, password))
            con.commit()
            print("Record successfully added to database")
          

        except Exception as e:
            con.rollback()
            print("Error in the INSERT")
            print(e)



        finally:
            con.close()

        
