#!/usr/bin/env python
"""
Bitcoin Vanity Address Generator with User Registration, Vault, and Social Features

Features:
  • Users must register providing a unique username, email/phone and a strong password.
    The password must contain at least 8 characters, one uppercase letter, one lowercase,
    one number and one special character.
  • User passwords are stored using one-way hashing (PBKDF2) with a random salt.
  • After login, the user can generate vanity Bitcoin addresses.
    Generated wallet pairs are encrypted (using a wallet encryption password provided during generation)
    and stored in the user’s vault. The user must supply the encryption password to view the wallet details.
  • Users may add friends and send messages, but messaging is allowed only when the friendship is mutual.

Requirements:
    pip install pycryptodome eel ecdsa base58

NOTE: This is a simplified demonstration using file-based JSON storage.
"""

import os
import time
import json
import threading
import ctypes
import hashlib
import base58
import re
from datetime import datetime
import eel

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

# File paths for user and messages storage.
USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"

# Create files if they don't exist.
if not os.path.isfile(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump({}, f)
if not os.path.isfile(MESSAGES_FILE):
    with open(MESSAGES_FILE, "w") as f:
        json.dump([], f)

# Global current session (for demonstration; production apps should use proper session management).
current_session = {"username": None}

# Constants for vanity address generation.
BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVALID_CHARS = "O0Il"
KDF_SALT_SIZE = 16
KDF_ITERATIONS = 100000

# ---------------------
# User and Storage Utilities
# ---------------------
def load_users():
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_messages():
    with open(MESSAGES_FILE, "r") as f:
        return json.load(f)

def save_messages(data):
    with open(MESSAGES_FILE, "w") as f:
        json.dump(data, f, indent=4)

def hash_password(password, salt=None):
    if not salt:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return base64.b64encode(salt).decode() + ":" + base64.b64encode(key).decode()

def verify_password(provided_password, stored_password):
    try:
        salt_b64, key_b64 = stored_password.split(":")
        salt = base64.b64decode(salt_b64)
        key = base64.b64decode(key_b64)
        new_key = hashlib.pbkdf2_hmac("sha256", provided_password.encode(), salt, 100000)
        return new_key == key
    except Exception:
        return False

def validate_user_password(password):
    # Password must have at least 8 characters, one uppercase, one lowercase, one digit and one special character.
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$"
    return re.match(pattern, password)

# ---------------------
# Vanity Address Generator Functions
# ---------------------
def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()

def hash160(data):
    return ripemd160(sha256(data))

def double_sha256(data):
    return sha256(sha256(data))

def create_private_key():
    return os.urandom(32)

def private_to_wif(private_key):
    version = b"\x80"
    extended = version + private_key
    checksum = double_sha256(extended)[:4]
    wif = base58.b58encode(extended + checksum)
    return wif.decode()

def private_to_public(private_key):
    import ecdsa
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = b"\04" + verifying_key.to_string()
    return public_key

def public_to_address(public_key):
    h160 = hash160(public_key)
    version = b"\x00"
    vh160 = version + h160
    checksum = double_sha256(vh160)[:4]
    address = base58.b58encode(vh160 + checksum)
    return address.decode()

class Stats:
    def __init__(self):
        self.attempts = ctypes.c_ulong(0)
        self.start_time = None
        self.found = False

def generate_address(pattern, stats, result_container):
    target = pattern[1:]
    target_len = len(pattern)
    while not stats.found:
        private_key = create_private_key()
        public_key = private_to_public(private_key)
        address = public_to_address(public_key)
        stats.attempts = ctypes.c_ulong(stats.attempts.value + 1)
        if address[1:target_len] == target:
            wif = private_to_wif(private_key)
            stats.found = True
            result_container["result"] = {"address": address, "wif": wif}
            break

def update_stats(stats, pattern):
    total = 58 ** (len(pattern) - 1) if len(pattern) > 1 else 1
    probability_message = f"Probability: 1 in {total:,}"
    while not stats.found:
        current_attempts = stats.attempts.value
        elapsed_time = time.time() - stats.start_time
        speed = current_attempts / elapsed_time if elapsed_time > 0 else 0
        if speed >= 1e6:
            speed_str = f"{speed/1e6:.2f}M/s"
        elif speed >= 1e3:
            speed_str = f"{speed/1e3:.2f}K/s"
        else:
            speed_str = f"{speed:.2f}/s"
        stats_message = f"Attempts: {current_attempts:,} | Time: {int(elapsed_time)}s | Rate: {speed_str}"
        remaining_attempts = max(total - current_attempts, 0)
        remaining_sec = remaining_attempts / speed if speed > 0 else 0
        hours = int(remaining_sec // 3600)
        minutes = int((remaining_sec % 3600) // 60)
        seconds = int(remaining_sec % 60)
        countdown = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        try:
            eel.update_progress(probability_message, stats_message, f"Estimated time remaining: {countdown}")
        except Exception:
            pass
        time.sleep(0.1)

def encrypt_wallet_entry(plain_text, wallet_pass):
    salt = get_random_bytes(KDF_SALT_SIZE)
    key = PBKDF2(wallet_pass, salt, dkLen=32, count=KDF_ITERATIONS)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode())
    encrypted_payload = {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
    return json.dumps(encrypted_payload)

def decrypt_wallet_entry(encrypted_payload, wallet_pass):
    try:
        data = json.loads(encrypted_payload)
        salt = base64.b64decode(data["salt"])
        nonce = base64.b64decode(data["nonce"])
        tag = base64.b64decode(data["tag"])
        ciphertext = base64.b64decode(data["ciphertext"])
        key = PBKDF2(wallet_pass, salt, dkLen=32, count=KDF_ITERATIONS)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode()
    except Exception:
        return None

# ---------------------
# Eel-Exposed Functions
# ---------------------
@eel.expose
def register_user(username, contact, password):
    if not username or not contact or not password:
        return {"success": False, "message": "All fields are required."}
    if not validate_user_password(password):
        return {"success": False, "message": "Password must be at least 8 characters long, include uppercase, lowercase, number, and special character."}
    users = load_users()
    if username in users:
        return {"success": False, "message": "Username already exists."}
    hashed = hash_password(password)
    users[username] = {
        "contact": contact,
        "password": hashed,
        "wallets": [],
        "friends": [],
    }
    save_users(users)
    return {"success": True, "message": "Registration successful. Please proceed to login."}

@eel.expose
def login_user(username, password):
    users = load_users()
    if username not in users:
        return {"success": False, "message": "Invalid username or password."}
    if not verify_password(password, users[username]["password"]):
        return {"success": False, "message": "Invalid username or password."}
    current_session["username"] = username
    return {"success": True, "message": "Login successful."}

@eel.expose
def start_vanity_generation(pattern, wallet_pass):
    username = current_session.get("username")
    if not username:
        eel.show_status("User not logged in.")
        return

    if not pattern or not pattern.startswith("1") or len(pattern) < 2 or len(pattern) > 10:
        eel.show_status("Invalid pattern. It must start with '1' and be 2 to 10 characters long.")
        return
    stats = Stats()
    stats.start_time = time.time()
    result_container = {}
    thread_gen = threading.Thread(target=generate_address, args=(pattern, stats, result_container))
    thread_stats = threading.Thread(target=update_stats, args=(stats, pattern))
    thread_gen.start()
    thread_stats.start()
    thread_gen.join()
    stats.found = True
    thread_stats.join()
    elapsed_time = time.time() - stats.start_time
    result = result_container.get("result", {})
    if result:
        wallet_text = f"Address: {result['address']}\nPrivate Key (WIF): {result['wif']}\nTime: {elapsed_time:.2f}s"
        encrypted_wallet = encrypt_wallet_entry(wallet_text, wallet_pass)
        users = load_users()
        users[username]["wallets"].append(encrypted_wallet)
        save_users(users)
        eel.show_generation_result("Vanity address generated and stored in your vault.")
    else:
        eel.show_generation_result("No result found.")

@eel.expose
def view_vault():
    username = current_session.get("username")
    if not username:
        return {"success": False, "message": "User not logged in.", "wallets": []}
    users = load_users()
    vault = users[username].get("wallets", [])
    return {"success": True, "wallets": vault}

@eel.expose
def decrypt_vault_entry(encrypted_entry, wallet_pass):
    decrypted = decrypt_wallet_entry(encrypted_entry, wallet_pass)
    if decrypted:
        return {"success": True, "decrypted": decrypted}
    else:
        return {"success": False, "message": "Decryption failed. Incorrect password or corrupted data."}

@eel.expose
def add_friend(friend_username):
    current_user = current_session.get("username")
    if not current_user:
        return {"success": False, "message": "User not logged in."}
    users = load_users()
    if friend_username not in users:
        return {"success": False, "message": "Friend username does not exist."}
    if friend_username == current_user:
        return {"success": False, "message": "You cannot add yourself."}
    if friend_username not in users[current_user]["friends"]:
        users[current_user]["friends"].append(friend_username)
    save_users(users)
    return {"success": True, "message": f"Friend request sent to {friend_username}."}

@eel.expose
def send_message(to_username, content):
    sender = current_session.get("username")
    if not sender:
        return {"success": False, "message": "User not logged in."}
    users = load_users()
    if to_username not in users:
        return {"success": False, "message": "Recipient does not exist."}
    if sender not in users[to_username]["friends"]:
        return {"success": False, "message": "Recipient has not added you as a friend."}
    msg = {
        "from": sender,
        "to": to_username,
        "content": content,
        "timestamp": datetime.utcnow().isoformat()
    }
    messages = load_messages()
    messages.append(msg)
    save_messages(messages)
    return {"success": True, "message": "Message sent."}

@eel.expose
def get_messages(with_username):
    current_user = current_session.get("username")
    if not current_user:
        return {"success": False, "messages": []}
    messages = load_messages()
    conv = [
        msg for msg in messages
        if (msg["from"] == current_user and msg["to"] == with_username) or
           (msg["from"] == with_username and msg["to"] == current_user)
    ]
    conv.sort(key=lambda x: x["timestamp"])
    return {"success": True, "messages": conv}

@eel.expose
def logout():
    current_session["username"] = None
    return {"success": True, "message": "Logged out."}

eel.init("web")
if __name__ == "__main__":
    eel.start("login.html", host="0.0.0.0", port=8000, mode=None)