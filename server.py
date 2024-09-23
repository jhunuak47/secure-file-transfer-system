import socket
from crypto_utils import generate_rsa_key_pair, decrypt_aes_key_with_rsa, decrypt_file
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 65432

def start_server():
    private_key, public_key = generate_rsa_key_pair()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(public_key_bytes)

            encrypted_aes_key = conn.recv(512)
            aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key)

            encrypted_file_data = bytearray()
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                encrypted_file_data.extend(chunk)

            if len(encrypted_file_data) > 16:
                iv = encrypted_file_data[:16]
                ciphertext = encrypted_file_data[16:]
                decrypted_data = decrypt_file(iv + ciphertext, aes_key)

                with open('received_file.txt', 'wb') as f:
                    f.write(decrypted_data)

                print("File received and decrypted successfully.")
            else:
                print("No valid file data received.")

if __name__ == "__main__":
    start_server()
