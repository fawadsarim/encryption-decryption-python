import base64
import binascii
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def read_from_file(filename: str) -> str:
    """
    Read the contents of a text file and return them as a string.

    Args:
    filename (str): The name of the file to be read.

    Returns:
    str: The contents of the file.

    """
    try:
        with open(filename, "r") as file:
            contents = file.read()
        return contents
    except FileNotFoundError:
        print(f"Error: {filename} does not exist. Please try again")
        quit()

def decode_pattern(string: str) -> str:
    """
    Decode the string using the given pattern.

    Args:
    string (str): The string to be decoded.

    Returns:
    str: The decoded string.

    """
    try:
        encoded_string = base64.b64decode(string.encode('utf-8')).decode('utf-8')
        encoded_string = binascii.unhexlify(encoded_string.encode('utf-8')).decode('utf-8')
        encoded_string = base64.b64decode(encoded_string.encode('utf-8')).decode('utf-8')
        encoded_string = binascii.unhexlify(encoded_string.encode('utf-8')).decode('utf-8')
        encoded_string = base64.b64decode(encoded_string.encode('utf-8')).decode('utf-8')
        return encoded_string
    except binascii.Error:
        print("Error: Could not decode the string using the given pattern.")
        return None

def decrypt_string(key: int, ciphertext_b64: str) -> str:
    """
    Decrypt the ciphertext using the given key.

    Args:
    key (int): The key to be used for decryption.
    ciphertext_b64 (str): The ciphertext in base64 format.

    Returns:
    str: The decrypted plaintext.

    """
    try:
        key = str(key)
        ciphertext_b64 = str(ciphertext_b64)
        ciphertext_iv = base64.b64decode(ciphertext_b64.encode('utf-8'))
        iv = ciphertext_iv[:16]
        ciphertext = ciphertext_iv[16:]
        
        digest = hashlib.sha256()
        digest.update(key.encode('utf-8'))
        key = digest.digest()[:32]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
    except:
        raise Exception("Incorrect decryption key. Please try again with the correct key.")

def save_to_file(input_string):
    """
    This function takes a string as input and saves it to a text file in the same directory.

    Args:
    input_string (str): The string to be saved to the text file.

    Returns:
    None

    """
    filename = "decrypted_secret.txt"
    with open(filename, "w") as file:
        file.write(input_string)
    print(f"String successfully saved to {filename}")

filename = "encrypted_secret.txt"

encrypted_secret = read_from_file(filename)
decryption_key = input('Enter Decryption Key:')

result_string = decode_pattern(encrypted_secret)
result_string = decrypt_string(len(decryption_key),result_string)
result_string = decode_pattern(result_string)

save_to_file(result_string)
    