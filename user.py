

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

        

class tokens:
    def __init__(self,id,activetoken):
        self.id = id
        self.activetoken =activetoken
       
    

     
    @staticmethod
    def gettoken(id):
      
        print(type(id))
        print(id)
        user = None
        try:
            con = sqlite3.connect("database.db")
           
        
        except:
            print("problem in connecting to database")
       

        try:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute('SELECT * FROM tokens WHERE id = ? ', (id, ))
            rows = cur.fetchone()
            if not rows:
                return None
            else:
                user = tokens(id = rows[0],activetoken=rows[1])
                print("this is user from get method ",user)
                


        

            


        #user = db.execute("SELECT * FROM user").fetchall()
         
           
        except Exception as e:
            print(e)
        finally:
            con.close()
        
        return user
  
  
    
    @staticmethod
    def update(id,activetoken):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in user update function")
        try:
            cur.execute("UPDATE tokens SET activetoken = ?  WHERE id = ?",  (activetoken,id))

            con.commit()
            print("Record successfully updated to database")
          

        except Exception as e:
            con.rollback()
            print("Error in the UPDATE")
            print(e)



        finally:
            con.close()

     
    @staticmethod
    def create(id,activetoken):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in token create function")
        try:
            
            cur.execute("INSERT INTO tokens(id,activetoken) VALUES (?,?)",(id,activetoken))
            con.commit()
            print("Record successfully added to database")
          

        except Exception as e:
            con.rollback()
            print("Error in the INSERT")
            print(e)



        finally:
            con.close()




class conversation:
    def __init__(self,id,page,sender):
        self.id = id
        self.page =page
        self.sender = sender
       
    

     
    @staticmethod
    def getdata(id):
      
        print(type(id))
        print(id)
        user = None
        try:
            con = sqlite3.connect("database.db")
           
        
        except:
            print("problem in connecting to database")
       

        try:
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute('SELECT * FROM conversation WHERE id = ? ', (id, ))
            rows = cur.fetchone()
            if not rows:
                return None
            else:
                user = conversation(id = rows[0],page=rows[1],sender = rows[2])
                print("this is user from get method ",user)
                


        

            


        #user = db.execute("SELECT * FROM user").fetchall()
         
           
        except Exception as e:
            print(e)
        finally:
            con.close()
        
        return user
  
  
    
    @staticmethod
    def updatepage(id,page):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in user update function")
        try:
            cur.execute("UPDATE conversation SET page = ?  WHERE id = ?",  (page,id))

            con.commit()
            print("Record successfully updated to database")
          

        except Exception as e:
            con.rollback()
            print("Error in the UPDATE")
            print(e)



        finally:
            con.close()

     
    @staticmethod
    def create(id,page, sender):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in page create function")
        try:
            
            cur.execute("INSERT INTO conversation(id,page,sender) VALUES (?,?,?)",(id,page,sender))
            con.commit()
            print("Record successfully added to database")
          

        except Exception as e:
            con.rollback()
            print("Error in the INSERT")
            print(e)



        finally:
            con.close()

    @staticmethod
    def updatesender(id,sender):
        try:
            con = sqlite3.connect("database.db")
            cur = con.cursor()
        except:
            print("connection error in user update function")
        try:
            cur.execute("UPDATE conversation SET sender = ?  WHERE id = ?",  (sender,id))

            con.commit()
            print("Record successfully updated to database")
          

        except Exception as e:
            con.rollback()
            print("Error in the UPDATE")
            print(e)



        finally:
            con.close()

     