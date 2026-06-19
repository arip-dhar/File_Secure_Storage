import bcrypt
import jwt
import os
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Master system key used strictly for HMAC validation generation
HMAC_SYSTEM_KEY = b"super-secret-system-hmac-authentication-key-string"
JWT_SECRET = "super-cryptographic-secret-key-change-this-in-production"
ALGORITHM = "HS256"

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8') 

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return user_id
    except (jwt.ExpiredSignatureError, jwt.PyJWTError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

def generate_user_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    user_salt = secrets.token_hex(32)
    return private_pem, public_pem, user_salt

def generate_fresh_file_key() -> bytes:
    return Fernet.generate_key()

def encrypt_data_with_key(data: bytes, file_key: bytes) -> bytes:
    return Fernet(file_key).encrypt(data)

def decrypt_data_with_key(data: bytes, file_key: bytes) -> bytes:
    return Fernet(file_key).decrypt(data)

# --- NEW DATA INTEGRITY SIGNING ENGINES ---
def calculate_hmac(data: bytes) -> str:
    return hmac.new(HMAC_SYSTEM_KEY, data, hashlib.sha256).hexdigest()

def verify_hmac(data: bytes, expected_tag: str) -> bool:
    computed_tag = calculate_hmac(data)
    # Using constant-time comparison to completely defeat timing attacks
    return hmac.compare_digest(computed_tag, expected_tag)

def encrypt_file_key_with_public_key(file_key: bytes, public_key_pem: str) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    return public_key.encrypt(
        file_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_file_key_with_private_key(encrypted_key_bytes: bytes, private_key_pem: str) -> bytes:
    private_key = serialization.load_pem_private_key(private_key_pem.encode('utf-8'), password=None)
    return private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )