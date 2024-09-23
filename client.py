import socket
from crypto_utils import encrypt_file, encrypt_aes_key_with_rsa, generate_aes_key
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 65432

def start_client(file_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        public_key_bytes = s.recv(4096)
        public_key = serialization.load_pem_public_key(public_key_bytes)

        aes_key = generate_aes_key()
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
        s.sendall(encrypted_aes_key)

        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()

            encrypted_file_data = encrypt_file(file_data, aes_key)
            s.sendall(encrypted_file_data)

            print("File encrypted and sent to the server successfully.")
        except FileNotFoundError as e:
            print(f"Error encrypting file: {e}")
        except UnicodeDecodeError as e:
            print(f"Encoding error: {e}")

if __name__ == "__main__":
    file_path = 'File_path.txt'
    start_client(file_path)
