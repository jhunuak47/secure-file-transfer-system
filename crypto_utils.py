import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.backends import default_backend

def generate_aes_key():
    return os.urandom(32)

def encrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()

        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        padder = aes_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return iv + encrypted_data
    except Exception as e:
        print(f"Error encrypting file: {e}")
        raise

def decrypt_file(encrypted_data, key):
    try:
        iv = encrypted_data[:16]
        encrypted_file_data = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_file_data) + decryptor.finalize()

        unpadder = aes_padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return decrypted_data
    except ValueError as e:
        print(f"Padding error: {e}")
        raise

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_aes_key_with_rsa(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def save_private_key(private_key, file_path):
    with open(file_path, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=None
        ))

def load_private_key(file_path):
    with open(file_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def save_public_key(public_key, file_path):
    with open(file_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_public_key(file_path):
    with open(file_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

if __name__ == "__main__":
    private_key, public_key = generate_rsa_key_pair()
    save_private_key(private_key, 'private_key.pem')
    save_public_key(public_key, 'public_key.pem')

    aes_key = generate_aes_key()
    print(f"AES Key: {aes_key.hex()}")

    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
    print(f"Encrypted AES Key: {encrypted_aes_key.hex()}")

    decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)
    print(f"Decrypted AES Key: {decrypted_aes_key.hex()}")
