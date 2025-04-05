import socket
import threading
import json
import base64
import os
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

users = {}  

def handle_client(client_socket, addr):
    try:
        data = client_socket.recv(4096).decode()
        client_data = json.loads(data)
        client_id = client_data["id"]
        client_public_key = RSA.import_key(client_data["public_key"])

        session_key = os.urandom(32)  

        cipher_rsa = PKCS1_OAEP.new(client_public_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        client_socket.send(base64.b64encode(encrypted_session_key))

        data = client_socket.recv(4096).decode()
        if not data:
            return

        msg_data = json.loads(data)
        if msg_data.get("type") == "auth":
            encrypted_auth = msg_data["encrypted_data"]
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=base64.b64decode(encrypted_auth)[:16])
            decrypted_auth = cipher_aes.decrypt(base64.b64decode(encrypted_auth)[16:]).decode()
            action, username, password = decrypted_auth.split("|", 2)

            response = {}
            if action == 'R':
                if username in users:
                    response = {"status": "error", "message": "Username exists."}
                else:
                    salt = os.urandom(16)
                    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                    users[username] = (salt, hashed)
                    response = {"status": "success", "message": "Registered."}
            elif action == 'L':
                if username not in users:
                    response = {"status": "error", "message": "Username not found."}
                else:
                    salt, stored_hash = users[username]
                    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                    if hashed == stored_hash:
                        response = {"status": "success", "message": "Logged in."}
                    else:
                        response = {"status": "error", "message": "Invalid password."}
            else:
                response = {"status": "error", "message": "Invalid action."}

            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            nonce = cipher_aes.nonce
            ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(response).encode())
            encrypted_response = base64.b64encode(nonce + ciphertext).decode()
            client_socket.send(json.dumps({"encrypted_response": encrypted_response}).encode())

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5555))
    server.listen(5)
    print("Bank Server started")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()

if __name__ == "__main__":
    start_server()