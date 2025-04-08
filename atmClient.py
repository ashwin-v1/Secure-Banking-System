import tkinter as tk
from tkinter import messagebox
import socket
import json
import base64
import os
import hashlib
from Crypto.Cipher import AES
import time
import hmac

# Configuration
SERVER_IP = "localhost"
SERVER_PORT = 5555
KEY_FILE = "shared_key"

# Global variables
current_user = None
session_key = None
enc_key = None
mac_key = None
sock = None

# Load or generate shared key
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        shared_key = base64.b64decode(f.read())
else:
    shared_key = os.urandom(32)
    with open(KEY_FILE, "wb") as f:
        f.write(base64.b64encode(shared_key))

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

def connect_to_server():
    global sock
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))
        return True
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect to server: {str(e)}")
        return False

def authenticate(action, username, password, client_id):
    global current_user, session_key, enc_key, mac_key, sock
    
    try:
        # Generate client nonce for mutual authentication
        client_nonce = base64.b64encode(os.urandom(16)).decode()
        
        auth_data = f"{action}|{username}|{password}|{client_nonce}|{client_id}"
        encrypted_auth = encrypt_with_aes(shared_key, auth_data)

        auth_packet = json.dumps({
            "type": "auth", 
            "encrypted_data": encrypted_auth,
            "client_id": client_id
        })
        sock.send(auth_packet.encode())

        response = sock.recv(4096).decode()
        response_data = json.loads(response)
        encrypted_response = response_data.get("encrypted_response")
        
        if encrypted_response:
            decrypted_response = decrypt_with_aes(shared_key, encrypted_response)
            response_data = json.loads(decrypted_response)
        
        if response_data.get("status") == "success":
            # Verify server's returned nonce matches our original
            returned_nonce = response_data.get("nonce")
            if client_nonce != returned_nonce:
                raise ValueError("Server authentication failed - nonce mismatch")
            
            # Get session key and derive encryption keys
            session_key = base64.b64decode(response_data.get("newKey"))
            enc_key, mac_key = derive_keys(session_key)
            
            current_user = username
            return True
        else:
            messagebox.showerror("Authentication Failed", response_data.get("message", "Unknown error"))
            return False
            
    except Exception as e:
        messagebox.showerror("Error", f"Authentication error: {str(e)}")
        return False

def perform_transaction(action, amount=None):
    global enc_key, mac_key, sock
    
    try:
        transaction_data = json.dumps({
            "action": action,
            "amount": str(amount) if amount else "0",
            "timestamp": time.time(),
            "username": current_user
        })

        encrypted_tx = encrypt_with_aes(enc_key, transaction_data)
        mac = compute_mac(mac_key, encrypted_tx)

        packet = json.dumps({
            "type": "transaction",
            "data": encrypted_tx,
            "mac": mac,
            "username": current_user
        })
        sock.send(packet.encode())

        server_response = sock.recv(4096).decode()
        response_data = json.loads(server_response)
        server_mac = response_data.get("mac")
        encrypted_response = response_data.get("data")

        if compute_mac(mac_key, encrypted_response) != server_mac:
            messagebox.showerror("Security Error", "Transaction integrity check failed!")
            return None

        decrypted_response = decrypt_with_aes(enc_key, encrypted_response)
        return json.loads(decrypted_response)
        
    except Exception as e:
        messagebox.showerror("Error", f"Transaction failed: {str(e)}")
        return None

# Tkinter Frontend
def open_main_menu():
    main_menu = tk.Toplevel(root)
    main_menu.title("Account Dashboard")
    main_menu.geometry("350x300")

    tk.Label(main_menu, text=f"Welcome, {current_user}!", font=("Helvetica", 14)).pack(pady=10)

    def deposit():
        def confirm_deposit():
            try:
                amount = float(deposit_entry.get())
                if amount <= 0:
                    messagebox.showerror("Error", "Amount must be positive")
                    return
                
                response = perform_transaction("deposit", amount)
                if response and response.get("status") == "success":
                    messagebox.showinfo("Success", response.get("message", "Deposit successful"))
                    deposit_window.destroy()
                else:
                    messagebox.showerror("Error", response.get("message", "Deposit failed"))
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid amount")
        
        deposit_window = tk.Toplevel(main_menu)
        deposit_window.title("Deposit")
        deposit_window.geometry("250x150")

        tk.Label(deposit_window, text="Amount to deposit:").pack(pady=5)
        deposit_entry = tk.Entry(deposit_window)
        deposit_entry.pack(pady=5)
        tk.Button(deposit_window, text="Confirm", command=confirm_deposit).pack(pady=10)
        tk.Button(deposit_window, text="Cancel", command=deposit_window.destroy).pack(pady=5)

    def withdraw():
        def confirm_withdraw():
            try:
                amount = float(withdraw_entry.get())
                if amount <= 0:
                    messagebox.showerror("Error", "Amount must be positive")
                    return
                
                response = perform_transaction("withdraw", amount)
                if response and response.get("status") == "success":
                    messagebox.showinfo("Success", response.get("message", "Withdrawal successful"))
                    withdraw_window.destroy()
                else:
                    messagebox.showerror("Error", response.get("message", "Withdrawal failed"))
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid amount")
        
        withdraw_window = tk.Toplevel(main_menu)
        withdraw_window.title("Withdraw")
        withdraw_window.geometry("250x150")

        tk.Label(withdraw_window, text="Amount to withdraw:").pack(pady=5)
        withdraw_entry = tk.Entry(withdraw_window)
        withdraw_entry.pack(pady=5)
        tk.Button(withdraw_window, text="Confirm", command=confirm_withdraw).pack(pady=10)
        tk.Button(withdraw_window, text="Cancel", command=withdraw_window.destroy).pack(pady=5)

    def show_balance():
        response = perform_transaction("balance")
        if response:
            if response.get("status") == "success":
                balance = response.get("balance", 0.0)
                messagebox.showinfo("Balance", f"Your balance is: ${balance:.2f}")
            else:
                error_msg = response.get("message", "Failed to check balance")
                messagebox.showerror("Error", error_msg)
        else:
            messagebox.showerror("Error", "No response from server")

    def logout():
        main_menu.destroy()
        global current_user, session_key, enc_key, mac_key
        current_user = None
        session_key = None
        enc_key = None
        mac_key = None
        if sock:
            sock.close()
        show_main_window()

    tk.Button(main_menu, text="Deposit", width=20, command=deposit).pack(pady=5)
    tk.Button(main_menu, text="Withdraw", width=20, command=withdraw).pack(pady=5)
    tk.Button(main_menu, text="Check Balance", width=20, command=show_balance).pack(pady=5)
    tk.Button(main_menu, text="Logout", width=20, command=logout).pack(pady=10)

def open_login_window():
    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("300x250")

    tk.Label(login_window, text="ATM ID").pack(pady=5)
    atm_id_entry = tk.Entry(login_window)
    atm_id_entry.pack(pady=5)

    tk.Label(login_window, text="Username").pack(pady=5)
    username_entry = tk.Entry(login_window)
    username_entry.pack(pady=5)

    tk.Label(login_window, text="Password").pack(pady=5)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack(pady=5)

    def submit():
        atm_id = atm_id_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        if not atm_id or not username or not password:
            messagebox.showerror("Error", "All fields are required")
            return

        if not connect_to_server():
            return

        if authenticate("L", username, password, atm_id):
            messagebox.showinfo("Success", "Login successful!")
            login_window.destroy()
            root.withdraw()
            open_main_menu()
        else:
            sock.close()

    tk.Button(login_window, text="Submit", command=submit).pack(pady=10)
    tk.Button(login_window, text="Cancel", command=login_window.destroy).pack(pady=5)

def open_register_window():
    register_window = tk.Toplevel(root)
    register_window.title("Register")
    register_window.geometry("300x300")

    tk.Label(register_window, text="ATM ID").pack(pady=5)
    atm_id_entry = tk.Entry(register_window)
    atm_id_entry.pack(pady=5)

    tk.Label(register_window, text="Username").pack(pady=5)
    username_entry = tk.Entry(register_window)
    username_entry.pack(pady=5)

    tk.Label(register_window, text="Password").pack(pady=5)
    password_entry = tk.Entry(register_window, show="*")
    password_entry.pack(pady=5)

    tk.Label(register_window, text="Confirm Password").pack(pady=5)
    confirm_entry = tk.Entry(register_window, show="*")
    confirm_entry.pack(pady=5)

    def submit():
        atm_id = atm_id_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        confirm = confirm_entry.get()

        if not atm_id or not username or not password:
            messagebox.showerror("Error", "All fields are required")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match")
            return

        if not connect_to_server():
            return

        if authenticate("R", username, password, atm_id):
            messagebox.showinfo("Success", "Registration successful!")
            register_window.destroy()
            root.withdraw()
            open_main_menu()
        else:
            sock.close()

    tk.Button(register_window, text="Submit", command=submit).pack(pady=10)
    tk.Button(register_window, text="Cancel", command=register_window.destroy).pack(pady=5)

def show_main_window():
    root.deiconify()
    tk.Label(root, text="Secure Banking System", font=("Helvetica", 16, "bold")).pack(pady=20)
    tk.Button(root, text="Login", width=15, command=open_login_window).pack(pady=10)
    tk.Button(root, text="Register", width=15, command=open_register_window).pack()

# Main application
root = tk.Tk()
root.title("ATM Client")
root.geometry("300x200")
root.resizable(False, False)

show_main_window()

def on_closing():
    if sock:
        sock.close()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()