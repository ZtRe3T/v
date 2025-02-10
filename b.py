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

# Constantes para validação Base58 Bitcoin
BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
INVALID_CHARS = 'O0Il'  # Caracteres ambíguos não utilizados em Base58 Bitcoin

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
    target = pattern[1:]  # Remove o '1' inicial uma vez
    target_len = len(pattern)
    while not stats.found:
        private_key = create_private_key()
        public_key = private_to_public(private_key)
        address = public_to_address(public_key)
        
        with stats.attempts.get_lock():
            stats.attempts.value += 1
        
        # Comparação direta dos caracteres após o '1'
        if address[1:target_len] == target:
            wif = private_to_wif(private_key)
            stats.found = True
            queue.put((address, wif))
            break

def print_stats(stats, pattern):
    with tqdm(total=None, desc=f"Procurando padrão: {pattern}", unit="tentativas") as pbar:
        last_attempts = 0
        
        while not stats.found:
            current_attempts = stats.attempts.value
            new_attempts = current_attempts - last_attempts
            elapsed_time = time.time() - stats.start_time
            
            speed = calculate_speed(current_attempts, elapsed_time)
            
            pbar.set_postfix({
                "velocidade": format_speed(speed),
                "total": f"{current_attempts:,}",
                "tempo": f"{int(elapsed_time)}s"
            })
            pbar.update(new_attempts)
            
            last_attempts = current_attempts
            time.sleep(0.1)

def validate_pattern(pattern):
    if not pattern:
        return False, "O padrão não pode estar vazio."
    
    if not pattern.startswith('1'):
        return False, "O padrão deve começar com '1'."
    
    if len(pattern) < 2 or len(pattern) > 10:
        return False, "O padrão deve ter entre 2 e 10 caracteres."
    
    invalid_chars = set(pattern) - set(BASE58_CHARS)
    if invalid_chars:
        chars_list = "', '".join(invalid_chars)
        return False, f"Caracteres inválidos detectados: '{chars_list}'\n" \
                     f"Use apenas os seguintes caracteres:\n{BASE58_CHARS}"
    
    ambiguous_chars = set(pattern) & set(INVALID_CHARS)
    if ambiguous_chars:
        chars_list = "', '".join(ambiguous_chars)
        return False, f"Caracteres ambíguos detectados: '{chars_list}'\n" \
                     f"Para evitar confusão, não use: O, 0, I, l"

    return True, "Padrão válido!"

def print_help():
    print("\n=== Guia de Caracteres Válidos ===")
    print("Caracteres permitidos:")
    print(f"• Números: {BASE58_CHARS[:9]}")
    print(f"• Letras maiúsculas: {BASE58_CHARS[9:35]}")
    print(f"• Letras minúsculas: {BASE58_CHARS[35:]}")
    print("\nCaracteres não permitidos (ambíguos):")
    print(f"• {', '.join(INVALID_CHARS)}")
    print("\nExemplos válidos:")
    print("• 1ABC")
    print("• 1Bitcoin")
    print("• 1satoshi")
    print("\nExemplos inválidos:")
    print("• 1O0l (contém caracteres ambíguos)")
    print("• 1BTC! (contém caracteres especiais)")
    print("=" * 40 + "\n")

def signal_handler(signum, frame):
    print("\nOperação cancelada pelo usuário.")
    sys.exit(0)

def main():
    print("\n=== Gerador de Vanity Address Bitcoin ===")
    print("Desenvolvido por: AnesDiego")
    print("Data: 2025-01-22 18:58:54 UTC")
    print("=" * 40)
    
    print_help()

    while True:
        pattern = input("Digite o padrão desejado (ou 'ajuda' para ver o guia): ").strip()
        
        if pattern.lower() == 'ajuda':
            print_help()
            continue
        
        is_valid, message = validate_pattern(pattern)
        if not is_valid:
            print(f"\nErro: {message}\n")
            continue
        
        print(f"\nSucesso: {message}")
        break

    print(f"\nIniciando busca por endereço que começa com: {pattern}")
    print("Pressione Ctrl+C para cancelar a operação\n")

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
    print("Endereço encontrado!")
    print("=" * 40)
    print(f"Endereço: {address}")
    print(f"Chave Privada (WIF): {wif}")
    print("\nEstatísticas finais:")
    print(f"Tempo total: {elapsed_time:.2f} segundos")
    print(f"Total de tentativas: {total_attempts:,}")
    print(f"Velocidade média: {format_speed(final_speed)}")
    print("=" * 40)

if __name__ == "__main__":
    main()