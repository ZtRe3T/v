#!/usr/bin/env python
"""
Bitcoin Vanity Address Generator – English Version (Secure Result Encryption)

This application generates a Bitcoin vanity address matching a user-specified prefix.
The result is encrypted on the server using a key derived from the password provided by the user.
The encrypted payload is then sent to the client.
Additionally, a decryption function is provided so that the user can decrypt the result in a secure environment,
without inadvertently restarting the generation process.

IMPORTANT:
  • The encryption password is sent to the server over a secure connection (HTTPS in production) and is used only in memory.
  • For true end-to-end security, consider performing encryption entirely on the client side.
  
Requirements:
    pip install pycryptodome eel ecdsa base58
"""
import os
import time
import ctypes
import threading
import hashlib
import base58
import eel
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import json

# Constants
BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
INVALID_CHARS = 'O0Il'
KDF_SALT_SIZE = 16
KDF_ITERATIONS = 100000

class Stats:
    def __init__(self):
        self.attempts = ctypes.c_ulong(0)
        self.start_time = None
        self.found = False

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()

def hash160(data):
    return ripemd160(sha256(data))

def double_sha256(data):
    return sha256(sha256(data))

def create_private_key():
    return os.urandom(32)

def private_to_wif(private_key):
    version = b'\x80'
    extended = version + private_key
    checksum = double_sha256(extended)[:4]
    wif = base58.b58encode(extended + checksum)
    return wif.decode()

def private_to_public(private_key):
    import ecdsa
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    public_key = b'\04' + verifying_key.to_string()
    return public_key

def public_to_address(public_key):
    h160 = hash160(public_key)
    version = b'\x00'
    vh160 = version + h160
    checksum = double_sha256(vh160)[:4]
    address = base58.b58encode(vh160 + checksum)
    return address.decode()

def calculate_speed(attempts, elapsed_time):
    if elapsed_time == 0:
        return 0
    return attempts / elapsed_time

def format_speed(speed):
    if speed >= 1e6:
        return f"{speed/1e6:.2f}M/s"
    elif speed >= 1e3:
        return f"{speed/1e3:.2f}K/s"
    return f"{speed:.2f}/s"

def validate_pattern(pattern):
    if not pattern:
        return False, "Pattern cannot be empty."
    if not pattern.startswith('1'):
        return False, "Pattern must start with '1'."
    if len(pattern) < 2 or len(pattern) > 10:
        return False, "Pattern length must be between 2 and 10 characters."
    invalid_chars = set(pattern) - set(BASE58_CHARS)
    if invalid_chars:
        chars_list = "', '".join(invalid_chars)
        return False, f"Invalid characters: '{chars_list}'. Allowed: {BASE58_CHARS}"
    ambiguous_chars = set(pattern) & set(INVALID_CHARS)
    if ambiguous_chars:
        chars_list = "', '".join(ambiguous_chars)
        return False, f"Ambiguous characters: '{chars_list}'. Avoid: {INVALID_CHARS}"
    return True, "Valid pattern!"

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
            result_container['result'] = (address, wif)
            break

def update_stats(stats, pattern):
    total = 58 ** (len(pattern) - 1) if len(pattern) > 1 else 1
    probability_message = f"Probability: 1 in {total:,}"
    while not stats.found:
        current_attempts = stats.attempts.value
        elapsed_time = time.time() - stats.start_time
        speed = calculate_speed(current_attempts, elapsed_time)
        speed_str = format_speed(speed)
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

def encrypt_result(plain_text, user_password):
    salt = get_random_bytes(KDF_SALT_SIZE)
    key = PBKDF2(user_password, salt, dkLen=32, count=KDF_ITERATIONS)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode())
    encrypted_payload = {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }
    return json.dumps(encrypted_payload)

@eel.expose
def start_generation(pattern, user_password):
    is_valid, message = validate_pattern(pattern)
    if not is_valid:
        eel.update_progress(f"Error: {message}", "", "")
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
    final_attempts = stats.attempts.value
    final_speed = calculate_speed(final_attempts, elapsed_time)
    final_stats = f"Time: {elapsed_time:.2f}s | Attempts: {final_attempts:,} | Rate: {format_speed(final_speed)}"
    address, wif = result_container.get('result', ("", ""))
    plain_text = (
        f"Address Found!\n"
        f"Address: {address}\n"
        f"Private Key (WIF): {wif}\n"
        f"{final_stats}"
    )
    encrypted_payload = encrypt_result(plain_text, user_password)
    eel.show_result(encrypted_payload)

@eel.expose
def decrypt_result(encrypted_payload, user_password):
    try:
        data = json.loads(encrypted_payload)
        salt = base64.b64decode(data['salt'])
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['ciphertext'])
        key = PBKDF2(user_password, salt, dkLen=32, count=KDF_ITERATIONS)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        eel.show_decrypted_result(plaintext.decode())
    except Exception as e:
        eel.show_decrypted_result("Decryption failed. Incorrect password or corrupted data.")

eel.init('')

if __name__ == "__main__":
    eel.start('index.html', host="0.0.0.0", port=8000, mode=None)