"""
Audio Encryption Module
Handles encryption/decryption of audio files with playback capability
"""

import os
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

def derive_key(password, salt):
    """Derive encryption key from password using PBKDF2"""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 600000, dklen=32)

def encrypt_audio(password, input_path, output_path=None):
    """
    Encrypt audio file and save with .aenc extension.
    
    Args:
        password: Encryption password
        input_path: Path to audio file
        output_path: Optional output path
    
    Returns:
        str: Path to encrypted file
    """
    try:
        if not os.path.exists(input_path):
            raise FileNotFoundError("Audio file not found!")

        with open(input_path, "rb") as f:
            data = f.read()

        salt = get_random_bytes(16)
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # If user didn't specify output path, append .aenc
        if not output_path:
            output_path = input_path + ".aenc"

        with open(output_path, "wb") as f:
            [f.write(x) for x in (salt, cipher.nonce, tag, ciphertext)]

        return output_path
    except Exception as e:
        raise Exception(f"Audio encryption failed: {e}")


def decrypt_audio(password, input_path, output_path=None):
    """
    Decrypt encrypted audio file (.aenc) and restore it.
    
    Args:
        password: Decryption password
        input_path: Path to encrypted audio file
        output_path: Optional output path
    
    Returns:
        str: Path to decrypted file
    """
    try:
        with open(input_path, "rb") as f:
            salt, nonce, tag, ciphertext = [f.read(x) for x in (16, 16, 16, -1)]

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        # Restore original extension if none given
        if not output_path:
            if input_path.endswith(".aenc"):
                output_path = input_path[:-5]  # remove .aenc
            else:
                output_path = input_path + ".decrypted"

            # If the intended output already exists, avoid overwriting by choosing
            # a new unique filename (append _restoredN or timestamp). This avoids
            # PermissionError when original file is locked or protected.
            if os.path.exists(output_path):
                base, ext = os.path.splitext(output_path)
                for i in range(1, 101):
                    candidate = f"{base}_restored{i}{ext}"
                    if not os.path.exists(candidate):
                        output_path = candidate
                        break

            try:
                with open(output_path, "wb") as f:
                    f.write(data)
            except PermissionError:
                # As a last resort, try a timestamped filename in same directory
                base, ext = os.path.splitext(output_path)
                ts = datetime.now().strftime('%Y%m%d%H%M%S')
                alt = f"{base}_restored_{ts}{ext}"
                with open(alt, "wb") as f:
                    f.write(data)
                output_path = alt

        return output_path
    except Exception as e:
        raise Exception(f"Audio decryption failed: {e}")


def get_audio_info(file_path):
    """
    Get basic audio file information.
    
    Args:
        file_path: Path to audio file
    
    Returns:
        dict: Audio file information
    """
    try:
        size = os.path.getsize(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        
        # Basic info without heavy dependencies
        info = {
            'size': size,
            'extension': ext,
            'filename': os.path.basename(file_path),
            'is_encrypted': file_path.endswith('.aenc')
        }
        
        return info
    except Exception as e:
        return {'error': str(e)}


if __name__ == "__main__":
    print("=" * 70)
    print("Audio Encryption Module")
    print("=" * 70)
    print("\nThis module provides secure encryption for audio files:")
    print("  • Supports all audio formats (MP3, WAV, FLAC, OGG, etc.)")
    print("  • AES-256-GCM encryption")
    print("  • Encrypted files saved with .aenc extension")
    print("\n" + "=" * 70)