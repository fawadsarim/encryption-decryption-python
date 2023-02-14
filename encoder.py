import base64
import binascii
import hashlib
import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encoding_pattern(string: str) -> str:
    """
    Encodes a given string by applying the following steps:
    1. encode the string to UTF-8 and then apply base64 encoding to it
    2. encode the output of step 1 to UTF-8 and then apply hexlification to it
    3. repeat steps 1 and 2 twice

    Args:
    string (str): The input string to be encoded.

    Returns:
    str: The encoded string.
    """
    encoded_string = base64.b64encode(string.encode('utf-8')).decode('utf-8')
    encoded_string = binascii.hexlify(encoded_string.encode('utf-8')).decode('utf-8')
    encoded_string = base64.b64encode(encoded_string.encode('utf-8')).decode('utf-8')
    encoded_string = binascii.hexlify(encoded_string.encode('utf-8')).decode('utf-8')
    encoded_string = base64.b64encode(encoded_string.encode('utf-8')).decode('utf-8')
    return encoded_string

def encrypt_string(key: int, plaintext: str) -> str:
    """
    Encrypts a given plaintext string using AES in CBC mode.
    The key is first hashed using SHA-256 to obtain a 32-byte key.
    A random Initialization Vector (IV) of 16 bytes is also generated.
    The plaintext is then padded using PKCS#7 padding before encryption.

    Args:
    key (int): The key to be used for encryption.
    plaintext (str): The plaintext string to be encrypted.

    Returns:
    str: The encrypted string in base64 encoding.
    """
    iv = os.urandom(16)
    plaintext = str(plaintext)
    key = str(key)
    digest = hashlib.sha256()

    digest.update(key.encode('utf-8'))
    key = digest.digest()[:32]
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def save_to_file(input_string):
    """
    This function takes a string as input and saves it to a text file in the same directory.

    Args:
    input_string (str): The string to be saved to the text file.

    Returns:
    None

    """
    filename = "encrypted_secret.txt"
    with open(filename, "w") as file:
        file.write(input_string)
    print(f"String successfully saved to {filename}")



user_input = input("Type Your Secret: ")
encryption_key = input('Enter Entryption Key:')

result_string = encoding_pattern(user_input)
result_string = encrypt_string(len(encryption_key), result_string)
result_string = encoding_pattern(result_string)

save_to_file(result_string)
