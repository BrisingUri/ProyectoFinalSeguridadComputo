import os
import hmac
import hashlib
import secrets
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SECRET_PASSPHRASE = os.environ.get('APP_ENCRYPTION_KEY', 'SeguridadEnComputo_ProyectoFinal_AES256_Key_2026!')

def get_master_key():
    kdf = Scrypt(salt=b'seguridad_computo_salt_v1', length=32, n=2**14, r=8, p=1)
    return kdf.derive(SECRET_PASSPHRASE.encode('utf-8'))

MASTER_KEY = get_master_key()
NETWORK_SHARED_HEX = hashlib.sha256((SECRET_PASSPHRASE + '_NETWORK_TLS_LAYER').encode('utf-8')).hexdigest()

def encrypt_field(plain_text):
    if plain_text is None or plain_text == '':
        return ''
    text_str = str(plain_text)
    if text_str.startswith('enc:v1:'):
        return text_str

    iv = os.urandom(12)
    aesgcm = AESGCM(MASTER_KEY)
    ct_and_tag = aesgcm.encrypt(iv, text_str.encode('utf-8'), None)
    ciphertext = ct_and_tag[:-16]
    auth_tag = ct_and_tag[-16:]
    return f"enc:v1:{iv.hex()}:{auth_tag.hex()}:{ciphertext.hex()}"

def decrypt_field(cipher_text):
    if not cipher_text or not isinstance(cipher_text, str):
        return ''
    if not cipher_text.startswith('enc:v1:'):
        return cipher_text
    try:
        parts = cipher_text.split(':')
        if len(parts) == 5:
            iv = bytes.fromhex(parts[2])
            auth_tag = bytes.fromhex(parts[3])
            encrypted = bytes.fromhex(parts[4])
            ct_and_tag = encrypted + auth_tag
        elif len(parts) == 4:
            iv = bytes.fromhex(parts[2])
            ct_and_tag = bytes.fromhex(parts[3])
        else:
            return '[Formato de cifrado inválido]'

        aesgcm = AESGCM(MASTER_KEY)
        return aesgcm.decrypt(iv, ct_and_tag, None).decode('utf-8')
    except Exception:
        return '[Error al desencriptar dato]'

def decrypt_network_value(val):
    if not val or not isinstance(val, str) or not val.startswith('net:v1:'):
        return val
    try:
        parts = val.split(':')
        if len(parts) != 4:
            return val
        iv = bytes.fromhex(parts[2])
        ct_and_tag = bytes.fromhex(parts[3])
        net_key = bytes.fromhex(NETWORK_SHARED_HEX)
        aesgcm = AESGCM(net_key)
        return aesgcm.decrypt(iv, ct_and_tag, None).decode('utf-8')
    except Exception:
        return val

def hash_password(password):
    salt = os.urandom(16).hex()
    kdf = Scrypt(salt=salt.encode('utf-8'), length=64, n=2**14, r=8, p=1)
    derived = kdf.derive(str(password).encode('utf-8')).hex()
    return f"scrypt:{salt}:{derived}"

def verify_password(password, stored_hash):
    if not password or not stored_hash or not stored_hash.startswith('scrypt:'):
        return False
    try:
        parts = stored_hash.split(':')
        if len(parts) != 3:
            return False
        salt = parts[1]
        expected_hex = parts[2]
        kdf = Scrypt(salt=salt.encode('utf-8'), length=64, n=2**14, r=8, p=1)
        derived_hex = kdf.derive(str(password).encode('utf-8')).hex()
        return hmac.compare_digest(derived_hex, expected_hex)
    except Exception:
        return False

def _normalize_base32(secret_base32):
    clean = ''.join(c for c in str(secret_base32).upper() if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
    if not clean:
        clean = 'JBSWY3DPEHPK3PXP'
    missing_padding = len(clean) % 8
    if missing_padding != 0:
        clean += '=' * (8 - missing_padding)
    return clean

def generate_base32_secret():
    return pyotp.random_base32()

def generate_totp_token(secret_base32):
    try:
        clean = _normalize_base32(secret_base32)
        return pyotp.TOTP(clean).now()
    except Exception:
        return '000000'

def verify_totp_token(secret_base32, token):
    if not secret_base32 or not token:
        return False
    clean_token = str(token).strip()
    if not clean_token.isdigit() or len(clean_token) != 6:
        return False
    try:
        clean = _normalize_base32(secret_base32)
        return pyotp.TOTP(clean).verify(clean_token, valid_window=1)
    except Exception:
        return False

def generate_numeric_otp(digits=6):
    return ''.join(str(secrets.randbelow(10)) for _ in range(digits))

def hash_token(token):
    return hashlib.sha256(str(token).encode('utf-8')).hexdigest()