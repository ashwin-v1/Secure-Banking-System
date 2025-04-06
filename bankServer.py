import socket
import threading
import json
import base64
import os
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import time
import hmac

users = {}          
accounts = {}       

def compute_mac(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def encrypt_with_aes(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_with_aes(key, enc_message):
    raw = base64.b64decode(enc_message)
    nonce, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

def derive_keys(master_secret):
    enc_key = hashlib.sha256(master_secret + b'enc').digest()
    mac_key = hashlib.sha256(master_secret + b'mac').digest()
    return enc_key, mac_key

def handle_client(client_socket, addr):
    try:
        data = client_socket.recv(4096).decode()
        client_data = json.loads(data)
        client_id = client_data["id"]
        client_public_key = RSA.import_key(client_data["public_key"])

        session_key = os.urandom(32)
        enc_key, mac_key = derive_keys(session_key)

        cipher_rsa = PKCS1_OAEP.new(client_public_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        client_socket.send(base64.b64encode(encrypted_session_key))

        while True:
            data = client_socket.recv(4096).decode()
            if not data:
                break

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
                        accounts[client_id] = 0.0  # initialize account balance
                        response = {"status": "success", "message": "Registered."}
                elif action == 'L':
                    if username not in users:
                        response = {"status": "error", "message": "Username not found."}
                    else:
                        salt, stored_hash = users[username]
                        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                        if hashed == stored_hash:
                            if client_id not in accounts:
                                accounts[client_id] = 0.0
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

            elif msg_data.get("type") == "transaction":
                mac = msg_data.get("mac")
                encrypted_data = msg_data.get("data")

                if compute_mac(mac_key, encrypted_data) != mac:
                    print("MAC verification failed!")
                    continue

                decrypted_data = decrypt_with_aes(enc_key, encrypted_data)
                tx_data = json.loads(decrypted_data)
                action = tx_data["action"]
                amount = float(tx_data["amount"]) if tx_data["amount"] else 0.0

                if client_id not in accounts:
                    accounts[client_id] = 0.0

                if action == "deposit":
                    accounts[client_id] += amount
                    message = f"Deposited ${amount:.2f}. New balance: ${accounts[client_id]:.2f}"
                elif action == "withdraw":
                    if accounts[client_id] >= amount:
                        accounts[client_id] -= amount
                        message = f"Withdrew ${amount:.2f}. New balance: ${accounts[client_id]:.2f}"
                    else:
                        message = "Insufficient funds."
                elif action == "balance":
                    message = f"Current balance: ${accounts[client_id]:.2f}"
                else:
                    message = "Unknown action."

                log_entry = {
                    "client_id": client_id,
                    "timestamp": time.time(),
                    "action": action
                }

                log_data = json.dumps(log_entry)
                encrypted_log_entry = encrypt_with_aes(enc_key, log_data)

                with open("transaction_log.txt", "a") as f:
                    f.write(encrypted_log_entry + "\n")

                encrypted_response = encrypt_with_aes(enc_key, message)
                response_packet = {
                    "data": encrypted_response,
                    "mac": compute_mac(mac_key, encrypted_response)
                }
                client_socket.send(json.dumps(response_packet).encode())

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
