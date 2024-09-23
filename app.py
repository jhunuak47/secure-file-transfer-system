from flask import Flask, request, redirect, url_for, render_template
from werkzeug.utils import secure_filename
import os
import socket
from crypto_utils import generate_aes_key, encrypt_file

app = Flask(__name__)

# Set the upload folder
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Encrypt the file
        aes_key = generate_aes_key()  # Generate AES key
        encrypted_data = encrypt_file(file_path, aes_key)

        # Send the encrypted data to the server
        send_to_server(encrypted_data)

        return 'File uploaded and encrypted successfully!'

def send_to_server(encrypted_data):
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(encrypted_data)

if __name__ == '__main__':
    app.run(debug=True)
