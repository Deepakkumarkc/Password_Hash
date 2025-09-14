import os
import base64
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Parameters for Argon2 key derivation (tune for your security needs; these are moderate defaults for 2025 hardware)
ARGON2_TIME_COST = 4  # Iterations
ARGON2_MEMORY_COST = 2**16  # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_KEY_LENGTH = 32  # For AES-256
ARGON2_SALT_LENGTH = 16

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from master password using Argon2id."""
    return hash_secret_raw(
        secret=master_password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_KEY_LENGTH,
        type=Type.ID  # Argon2id variant for hybrid security
    )

def encrypt_password(plain_password: str, master_password: str) -> str:
    """Encrypt a password using AES-256-GCM with key derived from master password.
    Returns base64-encoded (salt + nonce + ciphertext + tag) for storage.
    """
    salt = os.urandom(ARGON2_SALT_LENGTH)
    key = derive_key(master_password, salt)
    
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plain_password.encode(), None)
    
    # Combine for storage: salt + nonce + ciphertext
    combined = salt + nonce + ciphertext
    return base64.urlsafe_b64encode(combined).decode()

def decrypt_password(encrypted_password: str, master_password: str) -> str:
    """Decrypt the stored encrypted password using the master password."""
    combined = base64.urlsafe_b64decode(encrypted_password)
    salt = combined[:ARGON2_SALT_LENGTH]
    nonce = combined[ARGON2_SALT_LENGTH:ARGON2_SALT_LENGTH + 12]
    ciphertext = combined[ARGON2_SALT_LENGTH + 12:]
    
    key = derive_key(master_password, salt)
    aesgcm = AESGCM(key)
    try:
        plain_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plain_bytes.decode()
    except InvalidTag:
        raise ValueError("Decryption failed: Invalid master password or tampered data.")

# Example usage as a simple CLI
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python script.py encrypt <master_pass> <plain_pass>")
        print("  python script.py decrypt <master_pass> <encrypted_pass>")
        sys.exit(1)
    
    action = sys.argv[1]
    master_pass = sys.argv[2]
    
    if action == "encrypt":
        if len(sys.argv) < 4:
            print("Missing plain_pass for encrypt.")
            sys.exit(1)
        plain_pass = sys.argv[3]
        encrypted = encrypt_password(plain_pass, master_pass)
        print(f"Encrypted (store this): {encrypted}")
    elif action == "decrypt":
        if len(sys.argv) < 4:
            print("Missing encrypted_pass for decrypt.")
            sys.exit(1)
        encrypted_pass = sys.argv[3]
        try:
            decrypted = decrypt_password(encrypted_pass, master_pass)
            print(f"Decrypted password: {decrypted}")
        except ValueError as e:
            print(e)
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")
