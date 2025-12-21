# File: crypto/rsa_tool.py
import rsa

KEY_SIZE = 1024

def generate_key_pair():
    """Tạo một cặp khóa (Public, Private)"""
    return rsa.newkeys(KEY_SIZE)

def encrypt_text(message_str, public_key):
    """Mã hóa chuỗi string bằng Public Key"""
    message_bytes = message_str.encode('utf-8')
    crypto_bytes = rsa.encrypt(message_bytes, public_key)
    return crypto_bytes

def decrypt_text(crypto_bytes, private_key):
    """Giải mã bytes bằng Private Key"""
    try:
        message_bytes = rsa.decrypt(crypto_bytes, private_key)
        return message_bytes.decode('utf-8')
    except rsa.Pkcs1DecryptionError:
        return None  # Trả về None nếu lỗi

def sign_text(message_str, private_key):
    """Ký số văn bản"""
    return rsa.sign(message_str.encode('utf-8'), private_key, 'SHA-256')

def verify_sign(message_str, signature, public_key):
    """Xác thực chữ ký"""
    try:
        rsa.verify(message_str.encode('utf-8'), signature, public_key)
        return True
    except rsa.Pkcs1VerificationError:
        return False