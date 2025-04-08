import socket
import threading
import json
import base64
import os
import hashlib
from Crypto.Cipher import AES
import time
import hmac

# Server state
users = {}               # username: (salt, hashed_password)
accounts = {}            # username: {'balance': float, 'transactions': list}
nonce_list = []          # Track used nonces for replay protection
lock = threading.Lock()  # Thread synchronization

# Shared key configuration
KEY_FILE = "shared_key"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        SHARED_KEY = base64.b64decode(f.read())
else:
    SHARED_KEY = os.urandom(32)
    with open(KEY_FILE, "wb") as f:
        f.write(base64.b64encode(SHARED_KEY))

def compute_mac(key, message):
    """Generate HMAC for message integrity verification"""
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()

def encrypt_with_aes(key, plaintext):
    """Encrypt data using AES in EAX mode"""
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    result = base64.b64encode(nonce + ciphertext).decode()

    # Outputs
    print(f"\n[ENCRYPTION]")
    print(f"Plaintext: {plaintext}")
    print(f"Nonce: {base64.b64encode(nonce).decode()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Base64 Encoded: {result}\n")

    return result


def decrypt_with_aes(key, enc_message):
    """Decrypt data using AES in EAX mode"""
    raw = base64.b64decode(enc_message)
    nonce, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext).decode()

    # Outputs
    print(f"\n[DECRYPTION]")
    print(f"Base64 Input: {enc_message}")
    print(f"Nonce: {base64.b64encode(nonce).decode()}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Decrypted Plaintext: {plaintext}\n")

    return plaintext


def derive_keys(master_secret):
    """Derive encryption and MAC keys from master secret"""
    enc_key = hashlib.sha256(master_secret + b'enc').digest()
    mac_key = hashlib.sha256(master_secret + b'mac').digest()
    return enc_key, mac_key

def log_transaction(username, action, amount, status):
    """Log transaction to file with timestamp and username"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "timestamp": timestamp,
        "username": username, 
        "action": action,
        "amount": float(amount),
        "status": status
    }
    with open("transaction_log.txt", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def handle_client_auth(client_socket, client_data):
    """Handle client authentication (register/login)"""
    try:
        encrypted_auth = client_data["encrypted_data"]
        decrypted_auth = decrypt_with_aes(SHARED_KEY, encrypted_auth)
        action, username, password, client_nonce, client_id = decrypted_auth.split("|", 4)

        # Replay attack protection
        with lock:
            if client_nonce in nonce_list:
                raise ValueError("Reused nonce detected - possible replay attack")
            nonce_list.append(client_nonce)

        response = {}
        if action == 'R':
            if username in users:
                response = {"status": "error", "message": "Username exists."}
            else:
                salt = os.urandom(32)
                hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                with lock:
                    users[username] = (salt, hashed)
                    # Initialize account with balance and transaction history
                    accounts[username] = {
                        'balance': 0.0,
                        'transactions': []
                    }
                response = {
                    "status": "success",
                    "message": "Registered successfully.",
                    "nonce": client_nonce,
                    "newKey": base64.b64encode(os.urandom(32)).decode()
                }
        elif action == 'L':
            if username not in users:
                response = {"status": "error", "message": "Username not found."}
            else:
                salt, stored_hash = users[username]
                hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
                if hmac.compare_digest(hashed, stored_hash):
                    with lock:
                        if username not in accounts:
                            # Initialize account if it doesn't exist
                            accounts[username] = {
                                'balance': 0.0,
                                'transactions': []
                            }
                    response = {
                        "status": "success",
                        "message": "Logged in successfully.",
                        "nonce": client_nonce,
                        "newKey": base64.b64encode(os.urandom(32)).decode(),
                        "balance": accounts[username]['balance']
                    }
                else:
                    response = {"status": "error", "message": "Invalid password."}
        else:
            response = {"status": "error", "message": "Invalid action."}

        # Always include the nonce in response for mutual authentication
        response["nonce"] = client_nonce
        encrypted_response = encrypt_with_aes(SHARED_KEY, json.dumps(response))
        return encrypted_response, response.get("newKey"), username if response.get("status") == "success" else None

    except Exception as e:
        print(f"Authentication error: {e}")
        error_response = {
            "status": "error",
            "message": "Authentication failed",
            "nonce": client_nonce if 'client_nonce' in locals() else ""
        }
        return encrypt_with_aes(SHARED_KEY, json.dumps(error_response)), None

def handle_client_transaction(client_socket, msg_data, username, enc_key, mac_key):
    """Handle client transaction requests"""
    try:
        # Verify MAC first
        if compute_mac(mac_key, msg_data["data"]) != msg_data["mac"]:
            raise ValueError("MAC verification failed")

        # Decrypt transaction data
        decrypted_data = decrypt_with_aes(enc_key, msg_data["data"])
        tx_data = json.loads(decrypted_data)
        action = tx_data["action"]
        amount = float(tx_data["amount"]) if tx_data.get("amount") else 0.0

        # Process transaction
        with lock:
            if username not in accounts:
                accounts[username] = {'balance': 0.0, 'transactions': []}

            account = accounts[username]
            transaction_record = {
                'action': action,
                'amount': amount,
                'timestamp': time.time(),
                'status': 'pending',
                'username': username  # Include username in the record
            }

            if action == "deposit":
                account['balance'] += amount
                transaction_record['status'] = 'success'
                message = f"Deposited ${amount:.2f}. New balance: ${account['balance']:.2f}"
            elif action == "withdraw":
                if account['balance'] >= amount:
                    account['balance'] -= amount
                    transaction_record['status'] = 'success'
                    message = f"Withdrew ${amount:.2f}. New balance: ${account['balance']:.2f}"
                else:
                    transaction_record['status'] = 'failed'
                    message = "Insufficient funds."
            elif action == "balance":
                transaction_record['status'] = 'success'
                message = f"Current balance: ${account['balance']:.2f}"
            else:
                transaction_record['status'] = 'failed'
                message = "Unknown action."

            # Record transaction
            account['transactions'].append(transaction_record)

        # Log transaction - MAKE SURE USERNAME IS PASSED HERE
        log_transaction(
            username=username,  # This is the critical line that was missing
            action=action,
            amount=amount,
            status=transaction_record['status']
        )

        # Prepare response
        response = {
            "status": transaction_record['status'],
            "message": message,
            "balance": account['balance']
        }
        encrypted_response = encrypt_with_aes(enc_key, json.dumps(response))
        response_packet = {
            "data": encrypted_response,
            "mac": compute_mac(mac_key, encrypted_response)
        }
        client_socket.send(json.dumps(response_packet).encode())

    except Exception as e:
        print(f"Transaction error: {e}")
        # Log failed transaction with username if available
        log_transaction(
            username=username if 'username' in locals() else "unknown",
            action=action if 'action' in locals() else "unknown",
            amount=amount if 'amount' in locals() else 0.0,
            status="error"
        )
        error_response = encrypt_with_aes(enc_key, json.dumps({
            "status": "error",
            "message": str(e)
        }))
        client_socket.send(json.dumps({
            "data": error_response,
            "mac": compute_mac(mac_key, error_response)
        }).encode())

def handle_client(client_socket, addr):
    """Main client handling function"""
    try:
        print(f"New connection from {addr}")
        data = client_socket.recv(4096).decode()
        if not data:
            return

        client_data = json.loads(data)
        session_key = None
        enc_key, mac_key = None, None

        # Initial authentication
        if client_data.get("type") == "auth":
            encrypted_response, session_key_b64, username = handle_client_auth(client_socket, client_data)
            client_socket.send(json.dumps({"encrypted_response": encrypted_response}).encode())
            
            if session_key_b64:
                session_key = base64.b64decode(session_key_b64)
                enc_key, mac_key = derive_keys(session_key)

        # Process subsequent transactions if authenticated
        if session_key:
            while True:
                data = client_socket.recv(4096).decode()
                if not data:
                    break

                msg_data = json.loads(data)
                if msg_data.get("type") == "transaction":
                    handle_client_transaction(
                        client_socket, 
                        msg_data, 
                        username, 
                        enc_key, 
                        mac_key
                    )

    except Exception as e:
        print(f"Client handling error: {e}")
    finally:
        client_socket.close()
        print(f"Connection closed with {addr}")

def start_server():
    """Start the server and listen for connections"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 5555))
    server.listen(5)
    print("Bank Server started on port 5555")

    try:
        while True:
            client_socket, addr = server.accept()
            threading.Thread(
                target=handle_client,
                args=(client_socket, addr),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        server.close()

if __name__ == "__main__":
    start_server()