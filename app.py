#!/usr/bin/env python
import os
import hashlib
import base58
import ecdsa
from multiprocessing import Value
import time
import ctypes
import threading
import eel

# Constants
BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
INVALID_CHARS = 'O0Il'

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

def validate_pattern(pattern):
    if not pattern:
        return False, "O padrão não pode ser vazio."
    if not pattern.startswith('1'):
        return False, "O padrão deve começar com '1'."
    if len(pattern) < 2 or len(pattern) > 10:
        return False, "O padrão deve ter entre 2 e 10 caracteres."
    invalid_chars = set(pattern) - set(BASE58_CHARS)
    if invalid_chars:
        chars_list = "', '".join(invalid_chars)
        return False, f"Caracteres inválidos: '{chars_list}' - use: {BASE58_CHARS}"
    ambiguous_chars = set(pattern) & set(INVALID_CHARS)
    if ambiguous_chars:
        chars_list = "', '".join(ambiguous_chars)
        return False, f"Caracteres ambíguos: '{chars_list}' - evite: {INVALID_CHARS}"
    return True, "Padrão válido!"

def generate_address(pattern, stats, result_container):
    # target: everything after the first character ('1')
    target = pattern[1:]
    target_len = len(pattern)
    while not stats.found:
        private_key = create_private_key()
        public_key = private_to_public(private_key)
        address = public_to_address(public_key)
        with stats.attempts.get_lock():
            stats.attempts.value += 1
        if address[1:target_len] == target:
            wif = private_to_wif(private_key)
            stats.found = True
            result_container['result'] = (address, wif)
            break

def update_stats(stats, pattern):
    # Calculate fixed probability based on the pattern length.
    if len(pattern) <= 1:
        total = 1
    else:
        total = 58 ** (len(pattern) - 1)
    probability_message = f"Probabilidade: 1 em {total:,}"
    while not stats.found:
        current_attempts = stats.attempts.value
        elapsed_time = time.time() - stats.start_time
        speed = calculate_speed(current_attempts, elapsed_time)
        speed_str = format_speed(speed)
        stats_message = f"Tentativas: {current_attempts:,} | Tempo: {int(elapsed_time)}s | Taxa: {speed_str}"
        # Calculate estimated remaining time in seconds.
        remaining_attempts = max(total - current_attempts, 0)
        remaining_sec = remaining_attempts / speed if speed > 0 else 0
        # Format remaining_sec into HH:MM:SS
        hours = int(remaining_sec // 3600)
        minutes = int((remaining_sec % 3600) // 60)
        seconds = int(remaining_sec % 60)
        countdown = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        estimate_message = f"Tempo restante: {countdown}"
        # Update progress in the UI with three fields.
        try:
            eel.update_progress(probability_message, stats_message, estimate_message)
        except Exception as e:
            # In case the Eel JS function isn't ready, ignore errors.
            pass
        time.sleep(0.1)

@eel.expose
def start_generation(pattern):
    is_valid, message = validate_pattern(pattern)
    if not is_valid:
        eel.update_progress(f"Erro: {message}", "", "")
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
    final_stats = f"Tempo: {elapsed_time:.2f}s | Tentativas: {final_attempts:,} | Taxa: {format_speed(final_speed)}"
    address, wif = result_container.get('result', ("", ""))
    eel.show_result(address, wif, final_stats)

# Initialize Eel pointing to the current folder where index.html is located.
eel.init('')

if __name__ == "__main__":
    eel.start('index.html', host='0.0.0.0', port=8000, mode=None)