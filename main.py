import os
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def timing_decorator(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"{func.__name__} zajęło {round(elapsed_time, 3)}s")
        return result
    return wrapper


@timing_decorator
def szyfrowanie(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    return iv, ciphertext


@timing_decorator
def deszyfrowanie(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.decode()


def main(): 
    KEYS = [
        b'qwertyuiopasdfgh',
        b'qwertyuiopasdfghjklzxcvb',
        b'qwertyuiopasdfghjklzxcvblogyuwrt'
    ]
    messages = []
    FILE_PATHS = ['rsa_1mb.txt', 'rsa_2mb.txt', 'rsa_5mb.txt']

    for file_path in FILE_PATHS:
        with open(file_path, 'r') as file:
            new_msg = file.read()
        messages.append((new_msg, file_path))

    for msg, file_path in messages:
        for key in KEYS:
            print(
                f"Rozmiar pliku: {file_path[4:7]}, długość klucza w bitach: {len(key*8)}")
            init_vect, ciphertext = szyfrowanie(key, msg)
            deszyfrowanie(key, init_vect, ciphertext)
            print('', end='\n')


if __name__ == '__main__':
    main()
