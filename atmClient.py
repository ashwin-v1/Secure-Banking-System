import socket
import json
import base64
import os
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import time
import hmac

SERVER_IP = "localhost"
SERVER_PORT = 5555

KEY_FILE = "client_rsa.pem"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        key = RSA.import_key(f.read())
else:
    key = RSA.generate(2048)
    with open(KEY_FILE, "wb") as f:
        f.write(key.export_key())

public_key = key.publickey().export_key().decode()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, SERVER_PORT))

client_id = input("Enter your client ID (e.g., ATM1): ")
auth_packet = json.dumps({"id": client_id, "public_key": public_key})
sock.send(auth_packet.encode())

encrypted_session_key = base64.b64decode(sock.recv(4096))
cipher_rsa = PKCS1_OAEP.new(key)
session_key = cipher_rsa.decrypt(encrypted_session_key)

print(f"[{client_id}] Secure session established.")

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

while True:
    action = input("Register (R) or Login (L): ").strip().upper()
    if action in ['R', 'L']:
        break
    print("Invalid choice. Please enter R or L.")

username = input("Username: ")
password = input("Password: ")

auth_data = f"{action}|{username}|{password}"
encrypted_auth = encrypt_with_aes(session_key, auth_data)

auth_packet = json.dumps({
    "type": "auth",
    "encrypted_data": encrypted_auth
})
sock.send(auth_packet.encode())

response = sock.recv(4096).decode()
try:
    response_data = json.loads(response)
    encrypted_response = response_data.get("encrypted_response")
    if encrypted_response:
        decrypted_response = decrypt_with_aes(session_key, encrypted_response)
        response_data = json.loads(decrypted_response)
    if response_data.get("status") == "success":
        print("Authentication successful.")
    else:
        print(f"Authentication failed: {response_data.get('message')}")
        sock.close()
        exit()
except Exception as e:
    print(f"Error processing response: {e}")
    sock.close()
    exit()

def derive_keys(master_secret):
    enc_key = hashlib.sha256(master_secret + b'enc').digest()
    mac_key = hashlib.sha256(master_secret + b'mac').digest()
    return enc_key, mac_key

master_secret = session_key 
enc_key, mac_key = derive_keys(master_secret)
print(f"Derived Encryption Key: {enc_key.hex()}")
print(f"Derived MAC Key: {mac_key.hex()}")

#--------------------------------------------Transactions--------------------------------------------
def compute_mac(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

while True:
    print("\nChoose an action:")
    print("1. Deposit")
    print("2. Withdraw")
    print("3. Balance Inquiry")
    print("4. Exit")
    choice = input("Enter your choice: ").strip()

    if choice == "4":
        print("Goodbye!")
        break

    if choice not in ["1", "2", "3"]:
        print("Invalid choice.")
        continue

    action_map = {"1": "deposit", "2": "withdraw", "3": "balance"}
    action = action_map[choice]
    amount = ""

    if action in ["deposit", "withdraw"]:
        amount = input("Enter amount: ").strip()

    transaction_data = json.dumps({
        "action": action,
        "amount": amount,
        "timestamp": time.time(),
        "client_id": client_id
    })

    encrypted_tx = encrypt_with_aes(enc_key, transaction_data)
    mac = compute_mac(mac_key, encrypted_tx)

    packet = json.dumps({
        "type": "transaction",
        "data": encrypted_tx,
        "mac": mac
    })
    sock.send(packet.encode())

    server_response = sock.recv(4096).decode()
    try:
        response_data = json.loads(server_response)
        server_mac = response_data.get("mac")
        encrypted_response = response_data.get("data")

        if compute_mac(mac_key, encrypted_response) != server_mac:
            print("Integrity check failed! Possible tampering.")
            continue

        decrypted_response = decrypt_with_aes(enc_key, encrypted_response)
        print("Server Response:", decrypted_response)

    except Exception as e:
        print(f"Error: {e}")
