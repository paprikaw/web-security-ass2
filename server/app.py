from flask import url_for
from flask import Flask
from flask import request
from flask import render_template
from flask import jsonify
from flask import redirect
from flask import session
from flask import send_from_directory
from flask import send_file

import re
import secrets
import json
import sqlite3
import os
import random
import string
import bleach
import csv

import hashlib # for md5 password hashing

# for sanitising file names, to prevent damage to the local filesystem
# when files are uploaded
from werkzeug.utils import secure_filename

app = Flask(__name__,static_folder='static', static_url_path='')

# set the app secret key to something cryptographically random
app.secret_key = secrets.token_hex(32)

# get the directory where this python file lives
APP_PATH = os.path.dirname(os.path.abspath(__file__))

def generate_password_hash(password):
    hsh = hashlib.md5(password.encode()).hexdigest()
    return hsh

def check_password_hash(hsh,password):
    if hsh == generate_password_hash(password):
        return True
    return False

# simulate an admin user who chooses a common password
# derived from https://en.wikipedia.org/wiki/List_of_the_most_common_passwords
ADMIN_PASSWORDS = ['123456',
                   'password',
                   '123456789',
                   'qwerty',
                   'abc123',
                   'qwertyuiop',
                   '111111',
                   'iloveyou',
                   '123123',
                   'qwerty123',
                   'admin',
                   '654321',
                   '555555',
                   'lovely',
                   '7777777',
                   'princess',
                   'dragon',
                   'donald',
                   'monkey',
                   'football',
                   'charlie',
                   'aa123456',
                   'freedom',
                   'letmein',
                   'trustno1',
                   'baseball',
                   'master',
                   'sunshine',
                   'shadow',
                   'superman',
                   'ninja',
                   'mustang',
                   'batman',
                   'starwars',
                   'solo',
                   'welcome',
                   'flower',
                   'loveme',
                   'whatever']

N=len(ADMIN_PASSWORDS)
app.logger.debug(f"There are {N} possible admin passwords")

def success(N):
    return 1.0/N

def fail(N):
    return (1.0 - success(N))

prob=(success(N) + fail(N)*success(N-1) + fail(N)*fail(N-1)*success(N-2))
app.logger.debug(f"Chance of random guessing succeeding is {int(prob*100)}%")

# we simulate an administrator to chooses a very common password
admin_password = random.choice(ADMIN_PASSWORDS)
admin_password_hash = generate_password_hash(admin_password)

app.logger.debug(f"admin password: {admin_password}")


def init_database():
    if os.path.isfile("database.db"):
        raise Exception("Database already exists!")
    
    connection = sqlite3.connect("database.db")
    sql = """
                DROP TABLE IF EXISTS messages;
                CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                postedby VARCHAR(64),
                content VARCHAR(140),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
                DROP TABLE IF EXISTS users;
                CREATE TABLE users ( 
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                username VARCHAR(64),
                password VARCHAR(100),
                login_attempts INTEGER DEFAULT 0);
                INSERT INTO users (username, password) VALUES ("admin", "%s");
              """ % admin_password_hash
    cursor = connection.cursor()
    cursor.executescript(sql)
    connection.close()

# re-initialise the database on app startup
init_database()

# check that the given path is part of this application
# this is to avoid reading+writing outside of our part of the filesystem
# due to untrusted input
def safe_path(path):
    if os.path.commonprefix((os.path.realpath(path),APP_PATH)) != APP_PATH:
        return False
    return True
    

ALLOWED_EXTENSIONS = ["csv", "json"]
    
def remove_cached_files(user):
    # invalidate any stored messages files
    for ext in ALLOWED_EXTENSIONS:
        filename = user+"."+ext
        os.system(f"rm -f {filename}")

    
@app.route('/admin', methods=['POST','GET'])
def admin():
    if 'username' not in session:
        return "Access denied", 403

    if session['username'] != "admin":
        return "Access denied", 403
    
    if request.method == 'GET':
        connection = sqlite3.connect("database.db")
        sql = "SELECT username FROM users;"
        cursor = connection.cursor()
        cursor.execute(sql)
        result = cursor.fetchall()
        connection.close()
        users = []
        for u in result:
            if u != 'admin':
                users.append(u[0])
        return render_template("admin.html",users=users)

    if not request.form['username']:
        return "No username given", 400
    
    user = request.form['username']

    if user != 'admin':
        response = delete_account()
        
    remove_cached_files(user)

    return "Removed account.", 200

def get_messages_for_user(username):
    connection = sqlite3.connect("database.db")    
    sql = "SELECT * FROM messages WHERE postedby=?;"
    cursor = connection.cursor()
    cursor.execute(sql,[username])
    result = cursor.fetchall()
    messages = []
    for r in result:
        msg = {"id": r[0], "postedby": r[1], "content": r[2], "timestamp": r[3]}
        messages.append(msg)
    return messages
    
@app.route('/')
def index():
    if 'username' in session:
        messages = get_messages_for_user(session['username'])
        return render_template('app.html', session=session,messages=messages)
    else:    
        return render_template("login.html")

@app.route('/deleteaccount', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return '<a href="/login">Log in</a> first'

    username=None
    if 'username' in request.form:
        username=request.form['username']
    
    # if none given, take it from the session
    if not username:
        username = session['username']
    else:
        # only admin is allowed to delete accounts other than their own
        if username != session['username'] and session['username'] != 'admin':
            return "Cannot delete another user's account", 403

    assert (username == session['username'] or session['username'] == 'admin')
    
    # cannot delete the admin account
    if username == 'admin':
        return "Admin account cannot be deleted", 400

    
    delete_msg_sql = "DELETE FROM messages WHERE postedby=?"
    delete_user_sql = "DELETE FROM users WHERE username=?"
    
    connection = sqlite3.connect("database.db")
    cursor = connection.cursor()            
    cursor.execute(delete_msg_sql,[username])
    cursor.execute(delete_user_sql,[username])
    connection.commit()
    connection.close()

    if session['username'] != 'admin':
        # force logout of non-admin users
        logout()
    
        return redirect('/')
    return "Account deleted OK", 200
    
@app.route('/deletemsg', methods=['POST'])
def delete_msg():
    if 'username' not in session:
        return '<a href="/login">Log in</a> first'

    id = request.form['id']
    if not id:
        return "No id parameter given"

    # a laborious way to determine if the user has permission to delete
    messages = get_messages_for_user(session['username'])
    for msg in messages:
        if int(msg['id']) == int(id):
            # found it, delete the message
            sql = "DELETE FROM messages WHERE id=?"
            connection = sqlite3.connect("database.db")
            cursor = connection.cursor()            
            cursor.execute(sql,[id])
            connection.commit()
            connection.close()

            remove_cached_files(session['username'])
            return redirect('/')
    return "You can delete no messge with that id", 400
            
    
    
@app.route('/download', methods=['GET','POST'])
def download_file():
    if 'username' not in session:
        return '<a href="/login">Log in</a> first'

    if request.method == 'POST':

        ext = request.form['extension']
        if ext not in ALLOWED_EXTENSIONS:
            return "Invalid extension", 400
        
        filename = session['username']+"."+ext
        # to avoid unnecessary computation, serve one if we already have one
        if os.path.exists(filename):
            return redirect(url_for('download_file',file=filename))

        messages = get_messages_for_user(session['username'])

        if ext == 'json':
            with open(filename, 'wb') as f:
                j = jsonify(messages)
                f.write(j.data)
                f.close()
        elif ext == 'csv':
            with open(filename, 'w', newline='') as csv_file:
                fieldnames = ['id', 'postedby', 'timestamp', 'content']
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                for msg in messages:
                    writer.writerow(msg)
        else:
            assert False and "Shouldn't get here"
                    
        return redirect(url_for('download_file',file=filename))
    else:
        if not request.args.get('file'):
            return render_template("download.html")

        filename=request.args.get('file')

        file_path = filename

        # validate the filename: should be of the form username.blah
        s = file_path.split('.')
        if len(s) != 2:
            return "Invalid filename", 400
        if s[0] != session['username']:
            return "Access denied: you can only download files &lt;username&gt;.&lt;ext&gt; where &lt;username&gt; is your username and &lt;ext&gt; is any file extension", 403
        
        if not safe_path(filename):
            return "Access denied", 403

        if not os.path.exists(file_path):
            return "File not found", 404

        return send_file(file_path,as_attachment=True)

        
@app.route('/login', methods=['GET', 'POST'])
def login():
    user = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        connection = sqlite3.connect("database.db")
        sql = "SELECT username,password,login_attempts FROM users WHERE username=?;"
        cursor = connection.cursor()
        cursor.execute(sql,[username])
        result = cursor.fetchall()
        connection.close()
        
        lockout=False
        if len(result) != 0:
            if result[0][2] < 3:
                if check_password_hash(result[0][1],password):
                    session['username'] = result[0][0]

                    # reset invalid login attempts counter
                    sql = "UPDATE users SET login_attempts = 0 WHERE username = ?"
                    connection = sqlite3.connect("database.db")
                    cursor = connection.cursor()            
                    cursor.execute(sql,[username])
                    connection.commit()
                    connection.close()
                
                    return redirect('/')
            
                # invalid login attempt
                sql = "UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ?"
                connection = sqlite3.connect("database.db")
                cursor = connection.cursor()            
                cursor.execute(sql,[username])
                connection.commit()
                connection.close()
            else:
                lockout=True                
        return render_template('login.html', error=True, lockout=lockout, user=None), 401
    else:
        return render_template('login.html',error=False,lockout=False,user=None), 200


@app.route('/post', methods=['POST'])
def post():
    if 'username' in session and request.form['msg']:
        username = session['username']
        msg = request.form['msg']
        # sanitise all messages
        msg = bleach.clean(msg)
        if len(msg) <= 140:
            
            remove_cached_files(session['username'])
            
            connection = sqlite3.connect("database.db")
            sql = 'INSERT INTO messages (postedby, content) VALUES (?, ?);'
            cursor = connection.cursor()
            cursor.execute(sql,[username,msg])
            connection.commit()
            connection.close()
            return redirect('/')
    if 'username' not in session:
        return f'<a href="/login">Log in</a> first.', 401
    else:
        return "No msg provided", 400
    

def sanitize_username(username):
    # Allow only alphanumeric, underscores, and hyphens
    sanitized_username = re.sub(r'[^a-zA-Z0-9_-]', '', username)
    # Limit length to 50 characters    
    sanitized_username = sanitized_username[:50]
    # Convert to lowercase
    sanitized_username = sanitized_username.lower()  
    return sanitized_username

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        s = sanitize_username(username)
        if s != username:
            return "Invalid username", 400
        
        password_hash = generate_password_hash(password)
        
        connection = sqlite3.connect("database.db")
        sql = "SELECT * FROM users WHERE username=?"
        cursor = connection.cursor()
        cursor.execute(sql,[username])
        result = cursor.fetchall()
        connection.close()
        if len(result) > 0:
            # user already exists
            return render_template('signup.html', error=True), 400
        else:
            connection = sqlite3.connect("database.db")
            sql = 'INSERT INTO users (username, password) VALUES (?, ?);'
            cursor = connection.cursor()
            cursor.execute(sql,[username,password_hash])
            connection.commit()
            connection.close()
            return redirect('login')
    return render_template('signup.html')

@app.route('/logout')
def logout():
    # Clear the session cookie
    session.pop('username', None)
    return redirect('/')

if __name__ == "__main__":
    # when debug=True, use_reloader needs to be False to prevent the
    # initialisation code (which generates the admin password, etc.)
    # from being executed more than once
    app.run(debug=True,host='0.0.0.0',port=80,use_reloader=False)
