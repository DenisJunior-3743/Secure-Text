"""
Simple Substitution Cipher Module

⚠️ SECURITY WARNING:
This module implements a simple substitution cipher for EDUCATIONAL purposes only.
It is NOT cryptographically secure and should NOT be used for:
- Protecting sensitive personal information (PII)
- Financial data, passwords, or credentials
- Any data requiring real security

For production use, consider:
- AES encryption (via Python's `cryptography` library)
- Proper key derivation (PBKDF2, Argon2, scrypt)
- Authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Format-preserving encryption (FPE) for numeric data

This implementation is vulnerable to:
- Frequency analysis attacks
- Known plaintext attacks
- Statistical analysis
"""

import string
import random
import hashlib
from typing import Tuple, Optional


# The character set used for mapping. Keep this stable between runs.
CHARS = " " + string.punctuation + string.ascii_letters + string.digits
CHARS_LIST = list(CHARS)


def key_to_string(key_list) -> str:
    """Convert key list to string representation"""
    return "".join(key_list)


def key_from_string(key_str: str):
    """Convert key string to list representation"""
    return list(key_str)


def generate_key(password: Optional[str] = None) -> list:
    """
    Return a shuffled key list. If password is provided the shuffle is
    deterministic (so the same password yields the same key).
    
    ⚠️ SECURITY NOTE: This uses SHA-256 as a simple hash, not a proper KDF.
    For real applications, use PBKDF2, Argon2, or scrypt with:
    - High iteration count (100,000+)
    - Salt (unique per user/message)
    - Proper key stretching
    """
    key = CHARS_LIST.copy()
    if password is None:
        random.shuffle(key)
    else:
        # Use a deterministic RNG seeded from the password hash
        # NOTE: This is NOT a cryptographically secure key derivation!
        digest = hashlib.sha256(password.encode('utf-8')).digest()
        seed = int.from_bytes(digest, 'big')
        rnd = random.Random(seed)
        rnd.shuffle(key)
    return key


def encrypt(plain_text: str, key_str: Optional[str] = None, password: Optional[str] = None) -> Tuple[str, str]:
    """
    Encrypt plain_text using the provided key_str or password.
    If neither key_str nor password is provided a random key will be generated.
    
    Returns:
        Tuple[str, str]: (cipher_text, key_str_used)
    
    ⚠️ SECURITY NOTE: This is a simple substitution cipher.
    - Each character always maps to the same encrypted character
    - Vulnerable to frequency analysis
    - Patterns in plaintext remain visible in ciphertext
    - Not suitable for sensitive data
    """
    if key_str is not None:
        key = key_from_string(key_str)
    else:
        key = generate_key(password)
        key_str = key_to_string(key)

    cipher_chars = []
    for ch in plain_text:
        try:
            idx = CHARS_LIST.index(ch)
            cipher_chars.append(key[idx])
        except ValueError:
            # If character is not in CHARS, leave it unchanged
            cipher_chars.append(ch)

    return ("".join(cipher_chars), key_str)


def decrypt(cipher_text: str, key_str: Optional[str] = None, password: Optional[str] = None) -> str:
    """
    Decrypt cipher_text using provided key_str or password. If password is
    provided the same deterministic key as generate_key(password) will be used.
    
    Args:
        cipher_text: The encrypted text to decrypt
        key_str: The encryption key string (if available)
        password: The password used during encryption (alternative to key_str)
    
    Returns:
        str: The decrypted plaintext
    
    Raises:
        ValueError: If neither key_str nor password is provided
    """
    if key_str is not None:
        key = key_from_string(key_str)
    elif password is not None:
        key = generate_key(password)
    else:
        raise ValueError("Either key_str or password must be provided for decryption")

    plain_chars = []
    for ch in cipher_text:
        try:
            idx = key.index(ch)
            plain_chars.append(CHARS_LIST[idx])
        except ValueError:
            # If character isn't found in key (e.g., it wasn't encrypted), keep it
            plain_chars.append(ch)

    return "".join(plain_chars)


# ============================================================================
# OPTIONAL: Example of how to use cryptography library for REAL encryption
# ============================================================================
"""
To use proper encryption, install: pip install cryptography

Example with Fernet (symmetric encryption):

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import os

def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
    '''Derive a proper encryption key from a password'''
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,  # High iteration count for security
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_secure(plaintext: str, password: str) -> dict:
    '''Encrypt using AES (via Fernet) with proper KDF'''
    key, salt = derive_key_from_password(password)
    f = Fernet(key)
    ciphertext = f.encrypt(plaintext.encode())
    return {
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'salt': base64.b64encode(salt).decode()
    }

def decrypt_secure(encrypted_data: dict, password: str) -> str:
    '''Decrypt using AES (via Fernet) with proper KDF'''
    salt = base64.b64decode(encrypted_data['salt'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    key, _ = derive_key_from_password(password, salt)
    f = Fernet(key)
    plaintext = f.decrypt(ciphertext)
    return plaintext.decode()
"""


if __name__ == "__main__":
    # Simple CLI that behaves similarly to the original script
    print("=" * 60)
    print("Simple Substitution Cipher CLI")
    print("=" * 60)
    print("\n⚠️  WARNING: This is NOT secure encryption!")
    print("For educational use only. Do not use for sensitive data.\n")
    print("=" * 60)
    
    mode = input("\nChoose (E)ncrypt or (D)ecrypt: ").strip().upper()
    
    if mode.startswith('E'):
        pt = input("Enter message to encrypt: ")
        pw = input("(optional) Enter password to derive key (leave blank for random): ")
        pw = pw or None
        cipher, key_used = encrypt(pt, password=pw)
        print(f"\n{'='*60}")
        print("Cipher text:")
        print(cipher)
        print(f"\n{'='*60}")
        print("Key (save this to decrypt later):")
        print(key_used)
        print(f"{'='*60}")
    else:
        ct = input("Enter message to decrypt: ")
        key_in = input("Enter key (paste the key string) or leave blank to use password: ")
        if key_in:
            plain = decrypt(ct, key_str=key_in)
        else:
            pw = input("Enter password used to derive key: ")
            plain = decrypt(ct, password=pw)
        print(f"\n{'='*60}")
        print("Decrypted:")
        print(plain)
        print(f"{'='*60}")