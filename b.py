import os
import hashlib
import base58
import ecdsa
from multiprocessing import Process, Queue, cpu_count, Value, Manager
import time
from datetime import datetime
import ctypes
from tqdm import tqdm
import signal
import sys
import re

# Constants for Bitcoin Base58 validation
BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
INVALID_CHARS = 'O0Il'  # Ambiguous characters not used in Bitcoin Base58

class Stats:
    def __init__(self):
        self.attempts = Value(ctypes.c_uint64, 0)
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

def generate_address(pattern, queue, stats, process_id):
    target = pattern[1:]  # Remove the initial '1'
    target_len = len(pattern)
    while not stats.found:
        private_key = create_private_key()
        public_key = private_to_public(private_key)
        address = public_to_address(public_key)
        
        with stats.attempts.get_lock():
            stats.attempts.value += 1
        
        # Direct comparison of characters after '1'
        if address[1:target_len] == target:
            wif = private_to_wif(private_key)
            stats.found = True
            queue.put((address, wif))
            break

def print_stats(stats, pattern):
    with tqdm(total=None, desc=f"Searching for pattern: {pattern}", unit="attempts") as pbar:
        last_attempts = 0
        
        while not stats.found:
            current_attempts = stats.attempts.value
            new_attempts = current_attempts - last_attempts
            elapsed_time = time.time() - stats.start_time
            
            speed = calculate_speed(current_attempts, elapsed_time)
            
            pbar.set_postfix({
                "speed": format_speed(speed),
                "total": f"{current_attempts:,}",
                "time": f"{int(elapsed_time)}s"
            })
            pbar.update(new_attempts)
            
            last_attempts = current_attempts
            time.sleep(0.1)

def validate_pattern(pattern):
    if not pattern:
        return False, "The pattern cannot be empty."
    
    if not pattern.startswith('1'):
        return False, "The pattern must start with '1'."
    
    if len(pattern) < 2 or len(pattern) > 10:
        return False, "The pattern must be between 2 and 10 characters long."
    
    invalid_chars = set(pattern) - set(BASE58_CHARS)
    if invalid_chars:
        chars_list = "', '".join(invalid_chars)
        return False, f"Invalid characters detected: '{chars_list}'\n" \
                     f"Use only the following characters:\n{BASE58_CHARS}"
    
    ambiguous_chars = set(pattern) & set(INVALID_CHARS)
    if ambiguous_chars:
        chars_list = "', '".join(ambiguous_chars)
        return False, f"Ambiguous characters detected: '{chars_list}'\n" \
                     f"To avoid confusion, do not use: O, 0, I, l"

    return True, "Valid pattern!"

def print_help():
    print("\n=== Valid Characters Guide ===")
    print("Allowed characters:")
    print(f"• Numbers: {BASE58_CHARS[:9]}")
    print(f"• Uppercase letters: {BASE58_CHARS[9:35]}")
    print(f"• Lowercase letters: {BASE58_CHARS[35:]}")
    print("\nAmbiguous characters (not allowed):")
    print(f"• {', '.join(INVALID_CHARS)}")
    print("\nValid examples:")
    print("• 1ABC")
    print("• 1Bitcoin")
    print("• 1satoshi")
    print("\nInvalid examples:")
    print("• 1O0l (contains ambiguous characters)")
    print("• 1BTC! (contains special characters)")
    print("=" * 40 + "\n")

def signal_handler(signum, frame):
    print("\nOperation cancelled by user.")
    sys.exit(0)

def main():
    print("\n=== Bitcoin Vanity Address Generator ===")
    print("Developed by: AnesDiego")
    print("Date: 2025-01-22 18:58:54 UTC")
    print("=" * 40)
    
    print_help()

    while True:
        pattern = input("Enter the desired pattern (or 'help' to view the guide): ").strip()
        
        if pattern.lower() == 'help':
            print_help()
            continue
        
        is_valid, message = validate_pattern(pattern)
        if not is_valid:
            print(f"\nError: {message}\n")
            continue
        
        print(f"\nSuccess: {message}")
        break

    print(f"\nStarting search for address beginning with: {pattern}")
    print("Press Ctrl+C to cancel the operation\n")

    signal.signal(signal.SIGINT, signal_handler)

    queue = Queue()
    stats = Stats()
    stats.start_time = time.time()

    processes = []
    num_processes = cpu_count()

    for i in range(num_processes):
        p = Process(target=generate_address, args=(pattern, queue, stats, i))
        p.start()
        processes.append(p)

    stats_process = Process(target=print_stats, args=(stats, pattern))
    stats_process.start()

    result = queue.get()
    stats.found = True
    
    stats_process.terminate()
    for p in processes:
        p.terminate()

    address, wif = result
    elapsed_time = time.time() - stats.start_time
    total_attempts = stats.attempts.value
    final_speed = calculate_speed(total_attempts, elapsed_time)

    print("\n" + "=" * 40)
    print("Address found!")
    print("=" * 40)
    print(f"Address: {address}")
    print(f"Private Key (WIF): {wif}")
    print("\nFinal Statistics:")
    print(f"Total time: {elapsed_time:.2f} seconds")
    print(f"Total attempts: {total_attempts:,}")
    print(f"Average speed: {format_speed(final_speed)}")
    print("=" * 40)

if __name__ == "__main__":
    main()