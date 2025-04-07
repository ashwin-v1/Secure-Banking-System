import socket
import json
import base64
import os
import hashlib
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

SERVER_IP = "127.0.0.1"
SERVER_PORT = 5555

KEY_FILE = "client_rsa.pem"

# Simulated user database and balance
user_data = {}
current_user = None
balance = 0.0

def open_main_menu():
    main_menu = tk.Toplevel(root)
    main_menu.title("Account Dashboard")
    main_menu.geometry("300x250")

    tk.Label(main_menu, text=f"Welcome, {current_user}!", font=("Helvetica", 14)).pack(pady=10)

    def deposit():
        def confirm_deposit():
            try:
                amount = float(deposit_entry.get())
                global balance
                balance += amount
                messagebox.showinfo("Deposit", f"${amount:.2f} deposited successfully.")
                deposit_window.destroy()
            except ValueError:
                messagebox.showerror("Error", "Enter a valid amount.")
        
        deposit_window = tk.Toplevel(main_menu)
        deposit_window.title("Deposit")
        deposit_window.geometry("250x120")

        tk.Label(deposit_window, text="Amount to deposit:").pack(pady=5)
        deposit_entry = tk.Entry(deposit_window)
        deposit_entry.pack(pady=5)
        tk.Button(deposit_window, text="Confirm", command=confirm_deposit).pack(pady=5)

    def withdraw():
        def confirm_withdraw():
            try:
                amount = float(withdraw_entry.get())
                global balance
                if amount > balance:
                    messagebox.showerror("Error", "Insufficient balance.")
                else:
                    balance -= amount
                    messagebox.showinfo("Withdraw", f"${amount:.2f} withdrawn successfully.")
                withdraw_window.destroy()
            except ValueError:
                messagebox.showerror("Error", "Enter a valid amount.")
        
        withdraw_window = tk.Toplevel(main_menu)
        withdraw_window.title("Withdraw")
        withdraw_window.geometry("250x120")

        tk.Label(withdraw_window, text="Amount to withdraw:").pack(pady=5)
        withdraw_entry = tk.Entry(withdraw_window)
        withdraw_entry.pack(pady=5)
        tk.Button(withdraw_window, text="Confirm", command=confirm_withdraw).pack(pady=5)

    def show_balance():
        messagebox.showinfo("Balance", f"Your balance is: ${balance:.2f}")

    tk.Button(main_menu, text="Deposit", width=20, command=deposit).pack(pady=5)
    tk.Button(main_menu, text="Withdraw", width=20, command=withdraw).pack(pady=5)
    tk.Button(main_menu, text="Show Balance", width=20, command=show_balance).pack(pady=5)

def open_login_window():
    login_window = tk.Toplevel(root)
    login_window.title("Login")
    login_window.geometry("300x200")

    tk.Label(login_window, text="Username").pack(pady=5)
    username_entry = tk.Entry(login_window)
    username_entry.pack(pady=5)

    tk.Label(login_window, text="Password").pack(pady=5)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.pack(pady=5)

    def login():
        username = username_entry.get()
        password = password_entry.get()
        global current_user, balance

        if username in user_data and user_data[username] == password:
            current_user = username
            balance = 0.0  # Reset or you can load from a persistent store
            messagebox.showinfo("Login", "Login successful!")
            login_window.destroy()
            open_main_menu()
        else:
            messagebox.showerror("Error", "Invalid credentials.")

    tk.Button(login_window, text="Submit", command=login).pack(pady=10)

def open_register_window():
    register_window = tk.Toplevel(root)
    register_window.title("Register")
    register_window.geometry("300x250")

    tk.Label(register_window, text="Username").pack(pady=5)
    username_entry = tk.Entry(register_window)
    username_entry.pack(pady=5)

    tk.Label(register_window, text="Password").pack(pady=5)
    password_entry = tk.Entry(register_window, show="*")
    password_entry.pack(pady=5)

    tk.Label(register_window, text="Confirm Password").pack(pady=5)
    confirm_entry = tk.Entry(register_window, show="*")
    confirm_entry.pack(pady=5)

    def register():
        username = username_entry.get()
        password = password_entry.get()
        confirm = confirm_entry.get()
        global current_user, balance

        if username in user_data:
            messagebox.showerror("Error", "Username already exists.")
        elif password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
        else:
            user_data[username] = password
            current_user = username
            balance = 0.0
            messagebox.showinfo("Register", "Account created!")
            register_window.destroy()
            open_main_menu()

    tk.Button(register_window, text="Register", command=register).pack(pady=10)

# Main window
root = tk.Tk()
root.title("Simple Banking System")
root.geometry("300x200")
root.resizable(False, False)

tk.Label(root, text="Welcome to the Secure Banking System", font=("Helvetica", 16, "bold")).pack(pady=20)
tk.Button(root, text="Login", width=15, command=open_login_window).pack(pady=10)
tk.Button(root, text="Register", width=15, command=open_register_window).pack()

root.mainloop()

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

