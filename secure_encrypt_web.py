import os
import base64
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from flask import Flask, request, render_template, jsonify

app = Flask(__name__)

# Parameters for Argon2 key derivation
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 2**16
ARGON2_PARALLELISM = 4
ARGON2_KEY_LENGTH = 32
ARGON2_SALT_LENGTH = 16

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from master password using Argon2id."""
    try:
        return hash_secret_raw(
            secret=master_password.encode('utf-8'),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_KEY_LENGTH,
            type=Type.ID
        )
    except Exception as e:
        print(f"Error in derive_key: {e}")
        raise

def encrypt_text(plain_text: str, master_password: str) -> str:
    """Encrypt text using AES-256-GCM with key derived from master password."""
    try:
        salt = os.urandom(ARGON2_SALT_LENGTH)
        key = derive_key(master_password, salt)
        if len(key) != ARGON2_KEY_LENGTH:
            raise ValueError(f"Derived key length mismatch: expected {ARGON2_KEY_LENGTH}, got {len(key)}")
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plain_text.encode('utf-8'), None)
        combined = salt + nonce + ciphertext
        return base64.urlsafe_b64encode(combined).decode('utf-8')
    except Exception as e:
        print(f"Error in encrypt_text: {e}")
        raise

def decrypt_text(encrypted_text: str, master_password: str) -> str:
    """Decrypt the stored encrypted text using the master password."""
    try:
        combined = base64.urlsafe_b64decode(encrypted_text)
        salt = combined[:ARGON2_SALT_LENGTH]
        nonce = combined[ARGON2_SALT_LENGTH:ARGON2_SALT_LENGTH + 12]
        ciphertext = combined[ARGON2_SALT_LENGTH + 12:]
        key = derive_key(master_password, salt)
        aesgcm = AESGCM(key)
        plain_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plain_bytes.decode('utf-8')
    except (InvalidTag, ValueError) as e:
        print(f"Decryption error: {e}")
        return "Decryption failed: Invalid master password or tampered data."

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        master_password = request.form.get('master_password')
        plain_text = request.form.get('plain_text')
        print(f"Received: master_password={master_password}, plain_text={plain_text}")  # Debug
        if not master_password or not plain_text:
            return jsonify({'error': 'Master password and plain text are required.'}), 400
        encrypted = encrypt_text(plain_text, master_password)
        return jsonify({'encrypted': encrypted})
    except Exception as e:
        print(f"Encryption error: {e}")
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        master_password = request.form.get('master_password')
        encrypted_text = request.form.get('encrypted_text')
        if not master_password or not encrypted_text:
            return jsonify({'error': 'Master password and encrypted text are required.'}), 400
        decrypted = decrypt_text(encrypted_text, master_password)
        return jsonify({'decrypted': decrypted})
    except Exception as e:
        print(f"Decryption error: {e}")
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)
