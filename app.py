from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

# Generate RSA keys
key_pair = RSA.generate(2048)
private_key = key_pair.export_key()
public_key = key_pair.publickey().export_key()

def aes_encrypt(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + encrypted_bytes).decode()

def aes_decrypt(encrypted_text, key):
    encrypted_bytes = base64.b64decode(encrypted_text)
    iv = encrypted_bytes[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes[AES.block_size:]), AES.block_size)
    return decrypted_bytes.decode()

def rsa_encrypt(text):
    recipient_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(recipient_key)
    encrypted_bytes = cipher.encrypt(text.encode())
    return base64.b64encode(encrypted_bytes).decode()

def rsa_decrypt(encrypted_text):
    private_rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_rsa_key)
    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_text))
    return decrypted_bytes.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    text = data.get('text')
    method = data.get('method')

    if method == 'AES':
        aes_key = b'0123456789abcdef'  # 16-byte key (for simplicity)
        encrypted_text = aes_encrypt(text, aes_key)
    elif method == 'RSA':
        encrypted_text = rsa_encrypt(text)
    else:
        return jsonify({'error': 'Invalid encryption method'}), 400

    return jsonify({'encrypted': encrypted_text})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_text = data.get('encrypted')
    method = data.get('method')

    if method == 'AES':
        aes_key = b'0123456789abcdef'  # Same key used in encryption
        decrypted_text = aes_decrypt(encrypted_text, aes_key)
    elif method == 'RSA':
        decrypted_text = rsa_decrypt(encrypted_text)
    else:
        return jsonify({'error': 'Invalid decryption method'}), 400

    return jsonify({'decrypted': decrypted_text})

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=8080)
