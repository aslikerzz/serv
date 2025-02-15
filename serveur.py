from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

app = Flask(__name__)

# Clé secrète et IV pour le serveur
SECRET_KEY = os.urandom(16)
CHALLENGE_FLAG = "FLAG{P4DD1NG_0R4CL3_M4ST3R}"

def pad(data):
    """PKCS7 padding"""
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    """PKCS7 unpadding"""
    padding_length = data[-1]
    if padding_length > 16:
        raise ValueError("Invalid padding")
    for i in range(1, padding_length + 1):
        if data[-i] != padding_length:
            raise ValueError("Invalid padding")
    return data[:-padding_length]

def encrypt(plaintext):
    """Chiffre le texte avec AES-CBC"""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = pad(plaintext.encode())
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_and_check_padding(ciphertext):
    """Déchiffre et vérifie le padding"""
    try:
        data = base64.b64decode(ciphertext)
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpad(plaintext_padded)
        return True
    except:
        return False

@app.route('/encrypt', methods=['POST'])
def encrypt_endpoint():
    """Endpoint pour chiffrer un message"""
    data = request.get_json()
    if 'plaintext' not in data:
        return jsonify({'error': 'Missing plaintext'}), 400
    
    ciphertext = encrypt(data['plaintext'])
    return jsonify({'ciphertext': ciphertext})

@app.route('/check_padding', methods=['POST'])
def check_padding_endpoint():
    """Endpoint pour vérifier le padding"""
    data = request.get_json()
    if 'ciphertext' not in data:
        return jsonify({'error': 'Missing ciphertext'}), 400
    
    is_valid = decrypt_and_check_padding(data['ciphertext'])
    return jsonify({'valid_padding': is_valid})

@app.route('/submit', methods=['POST'])
def submit_endpoint():
    """Endpoint pour soumettre la solution"""
    data = request.get_json()
    if 'decrypted_text' not in data:
        return jsonify({'error': 'Missing decrypted_text'}), 400
    
    if data['decrypted_text'] == "J'ai réussi l'attaque padding oracle!":
        return jsonify({'success': True, 'flag': CHALLENGE_FLAG})
    return jsonify({'success': False, 'message': 'Try again!'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
