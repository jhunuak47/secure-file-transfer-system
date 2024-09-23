import socket

# Server configuration
HOST = '127.0.0.1'  # The server's hostname or IP address (localhost in this case)
PORT = 65432        # The port used by the server

def connect_to_server():
    try:
        # Create a TCP/IP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"Connected to server at {HOST}:{PORT}")

            # Receive the public RSA key from the server
            public_key = s.recv(4096)  # Adjust buffer size as needed
            if public_key:
                print("Received Public Key from Server:")
                print(public_key.decode('utf-8'))
            else:
                print("No public key received from the server.")

    except ConnectionRefusedError:
        print(f"Could not connect to the server at {HOST}:{PORT}. Is the server running?")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    connect_to_server()
