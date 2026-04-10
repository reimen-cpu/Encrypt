"""
crypto_classic.py
=================
Algoritmos de cifrado clásico: AES-256-GCM y Fernet.

Este módulo extrae sin modificaciones la lógica criptográfica clásica que
existía originalmente en Encrypt.py. Se mantiene como módulo separado para
facilitar el mantenimiento y pruebas independientes.

Dependencias:
    pip install cryptography

Funciones exportadas:
    aes_gcm_encrypt(plaintext, password) -> str   (payload JSON+base64)
    aes_gcm_decrypt(token, password)     -> str
    fernet_encrypt(plaintext, password)  -> str   (payload JSON+base64)
    fernet_decrypt(data, password)       -> str
"""

import os
import json
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ─────────────────────────────────────────────────────────────────────────────
#  Derivación de claves
# ─────────────────────────────────────────────────────────────────────────────

def _derive_key_scrypt(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave AES-256 (32 bytes) a partir de una contraseña usando Scrypt.

    Parámetros Scrypt seleccionados para balance seguridad/rendimiento en
    hardware de escritorio (n=2^14 ≈ 32 MB de memoria).

    Args:
        password: contraseña en texto plano
        salt: bytes aleatorios de sal (mínimo 16 bytes recomendado)

    Returns:
        Clave derivada de 32 bytes (256 bits)
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))


def _fernet_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Deriva una clave Fernet (32 bytes codificados en base64 URL-safe) usando
    PBKDF2-HMAC-SHA256 con 480.000 iteraciones (recomendación OWASP 2024).

    Args:
        password: contraseña en texto plano
        salt: bytes aleatorios de sal (mínimo 16 bytes recomendado)

    Returns:
        Clave Fernet en bytes (base64 URL-safe de 32 bytes)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


# ─────────────────────────────────────────────────────────────────────────────
#  AES-256-GCM
# ─────────────────────────────────────────────────────────────────────────────

def aes_gcm_encrypt(plaintext: str, password: str) -> str:
    """
    Cifra texto con AES-256-GCM derivando la clave desde una contraseña con Scrypt.

    Formato del payload retornado (base64 de JSON):
        {
            "version":    "1.0",
            "algorithm":  "AES-256-GCM",
            "salt":       "<base64>",
            "nonce":      "<base64>",
            "ciphertext": "<base64>"
        }

    Args:
        plaintext: texto a cifrar (UTF-8)
        password:  contraseña para derivar la clave

    Returns:
        Token cifrado (base64 de JSON)
    """
    salt  = os.urandom(16)
    nonce = os.urandom(12)
    key   = _derive_key_scrypt(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    payload = {
        "version":    "1.0",
        "algorithm":  "AES-256-GCM",
        "salt":       base64.b64encode(salt).decode(),
        "nonce":      base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def aes_gcm_decrypt(token: str, password: str) -> str:
    """
    Descifra un token producido por aes_gcm_encrypt().

    Args:
        token:    token cifrado (base64 de JSON)
        password: contraseña original

    Returns:
        Texto original descifrado (UTF-8)

    Raises:
        ValueError: si el token está corrupto o la contraseña es incorrecta
    """
    try:
        payload    = json.loads(base64.b64decode(token.encode()))
        salt       = base64.b64decode(payload["salt"])
        nonce      = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
    except Exception:
        raise ValueError("El token está corrupto o tiene un formato inválido.")

    key = _derive_key_scrypt(password, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Contraseña incorrecta o datos corruptos (AES-GCM).")

    return plaintext.decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
#  Fernet (AES-128-CBC + HMAC-SHA256)
# ─────────────────────────────────────────────────────────────────────────────

def fernet_encrypt(plaintext: str, password: str) -> str:
    """
    Cifra texto con Fernet (AES-128-CBC + HMAC-SHA256) derivando la clave
    desde una contraseña con PBKDF2-HMAC-SHA256.

    Formato del payload retornado (base64 de JSON):
        {
            "version":   "1.0",
            "algorithm": "Fernet",
            "salt":      "<base64>",
            "token":     "<fernet_token>"
        }

    Args:
        plaintext: texto a cifrar (UTF-8)
        password:  contraseña para derivar la clave

    Returns:
        Token cifrado (base64 de JSON)
    """
    salt = os.urandom(16)
    key  = _fernet_key_from_password(password, salt)
    f    = Fernet(key)
    token = f.encrypt(plaintext.encode("utf-8"))
    payload = {
        "version":   "1.0",
        "algorithm": "Fernet",
        "salt":      base64.b64encode(salt).decode(),
        "token":     token.decode(),
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def fernet_decrypt(data: str, password: str) -> str:
    """
    Descifra un token producido por fernet_encrypt().

    Args:
        data:     token cifrado (base64 de JSON)
        password: contraseña original

    Returns:
        Texto original descifrado (UTF-8)

    Raises:
        ValueError: si el token está corrupto o la contraseña es incorrecta
    """
    try:
        payload = json.loads(base64.b64decode(data.encode()))
        salt    = base64.b64decode(payload["salt"])
        token   = payload["token"].encode()
    except Exception:
        raise ValueError("El token está corrupto o tiene un formato inválido.")

    key = _fernet_key_from_password(password, salt)
    f   = Fernet(key)
    try:
        plaintext = f.decrypt(token)
    except InvalidToken:
        raise ValueError("Contraseña incorrecta o datos corruptos (Fernet).")

    return plaintext.decode("utf-8")
