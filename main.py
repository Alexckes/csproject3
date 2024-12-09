from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.fernet import Fernet
from pyargon2 import hash
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid

hostName = "localhost"
serverPort = 8080
NOT_MY_KEY = Fernet.generate_key() #using Fernet as my AES
f = Fernet(NOT_MY_KEY)

sqliteConnection = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = sqliteConnection.cursor() #creation of the database
sql_command = """CREATE TABLE IF NOT EXISTS keys(
kid INTEGER PRIMARY KEY AUTOINCREMENT,
key BLOB NOT NULL,
exp INTEGER NOT NULL
);"""
cursor.execute(sql_command)
sqliteConnection.commit()

sql_command = """CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP      
);"""
cursor.execute(sql_command)
sqliteConnection.commit()
sql_command = """CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,  
    FOREIGN KEY(user_id) REFERENCES users(id)
);"""
cursor.execute(sql_command)
sqliteConnection.commit()

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
expired_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)



pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

numbers = private_key.private_numbers()

token1 = f.encrypt(pem)
tokenX = f.encrypt(expired_pem)

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def convert_string_to_pem(key_string): #I tried to convert the returned string back to PEM form and gave up
    keyl = serialization.load_pem_private_key(
        data=key_string.encode(),
        password=None,
    )
    pelm = keyl.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pelm

dt = datetime.datetime.now()
seq1 = int(dt.strftime("%Y%m%d%H%M%S")) #converting datetime to an int
#leg = pem
#beg = expired_pem
dt = datetime.datetime.now() + datetime.timedelta(hours=1)
seq2 = int(dt.strftime("%Y%m%d%H%M%S"))
data = [
    (1,tokenX,0), 
    (2,token1,seq1),
]
cursor.executemany('INSERT INTO keys VALUES (?,?,?)',data) #adding two keys to the database, one marked as expired with 0 and one not marked as expired with a date
sqliteConnection.commit()



class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            sqliteConnection = sqlite3.connect('totally_not_my_privateKeys.db')
            cursor = sqliteConnection.cursor()
            #bes = str(cursor.execute('SELECT key FROM keys WHERE exp != 0').fetchone())
            #res = f.decrypt(bes)
            #les = str(res.fetchone()) #fetching the string key from the database
            #mes = les[3:(len(les) - 3)] #trying to format it
            #userinput = json.loads(params)
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                #bes = str(cursor.execute('SELECT key FROM keys WHERE exp == 0').fetchone())
                #res = f.decrypt(bes)
                #les = str(res.fetchone())
                #mes = les[3:(len(les) - 3)]
                #pelm = convert_string_to_pem(mes)
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers) #I gave up trying to plug some form of mes into here
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            
            #logs = {
            #    "id": 1,
            #    "request_ip": "127.0.0.1",
            #    "request_timestamp": datetime.datetime.utcnow(),
            #    "user_id": str(cursor.execute('SELECT id FROM users WHERE username == ?',"temp").fetchone())
            #}

            logs = (1,"127.0.0.1",datetime.datetime.utcnow(),1)
            #cursor.executemany('INSERT INTO auth_logs VALUES (?,?,?,?)',logs)
            sqliteConnection.commit()
            sqliteConnection.close()
            return
        if parsed_path.path == "/register":
            sqliteConnection = sqlite3.connect('totally_not_my_privateKeys.db')
            cursor = sqliteConnection.cursor()
            #userinput = json.loads(params)
            uuidpass = uuid.uuid4().hex
            username = "temp1"
            email = "temp2"
            hashpass = hash(uuidpass,"not a salt")
            self.send_response(200,uuidpass)
            self.end_headers()
            #userdata = {
            #    "id": 1,
            #    "username": username,
            #    "password_hash": hashpass,
            #    "email": email,
            #    "date_registered": datetime.datetime.utcnow(),
            #    "last_login": 0
            #}
            userdata = (1,username,hashpass,email,datetime.datetime.utcnow(),0)
            cursor.executemany('INSERT INTO users VALUES (?,?,?,?,?,?)',userdata)
            sqliteConnection.commit()
            sqliteConnection.close()
            return
        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self): #I didn't even get started on this part of the code yet
        if self.path == "/.well-known/jwks.json":
            sqliteConnection = sqlite3.connect('totally_not_my_privateKeys.db')
            cursor = sqliteConnection.cursor()
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            sqliteConnection.commit()
            sqliteConnection.close()
            return

        self.send_response(405)
        self.end_headers()
        return


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
