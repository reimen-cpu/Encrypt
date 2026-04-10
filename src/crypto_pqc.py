"""
crypto_pqc.py
=============
Criptografía Post-Cuántica (PQC) híbrida usando liboqs (Open Quantum Safe).

Este módulo implementa:

1. KEM HÍBRIDO (cifrado de datos):
   - ML-KEM-768 (Kyber) y HQC-KEM (si disponible)
   - Flujo: AES-256-GCM cifra los datos, KEM encapsula la clave AES
   - Responsabilidad del KEM: distribución segura de la clave simétrica
   - Responsabilidad del AES: cifrado efectivo de los datos

2. DSA POST-CUÁNTICA (firmas digitales):
   - ML-DSA (Dilithium nivel 3) — para rendimiento
   - SLH-DSA (SPHINCS+ SHA2-128S) — para máxima seguridad conservadora
   - Las firmas se aplican sobre el payload completo (ciphertext + metadata)

Principio de diseño (separación de responsabilidades):
   KEM  → distribución de claves (NO cifrado de datos)
   AES  → cifrado de datos (NO distribución de claves)
   DSA  → autenticidad/integridad (NO confidencialidad)

Dependencias:
    - liboqs_runtime (enlace con /usr/local/lib/liboqs.so)
    - key_manager (serialización de claves)
    - cryptography (AES-GCM para cifrado de datos)

Formato del payload KEM (base64 de JSON):
    {
        "version":        "2.0",
        "algorithm":      "ML-KEM-768",
        "kem_type":       "ML-KEM-768",
        "signature_type": "ML-DSA" | "SLH-DSA" | null,
        "kem_ciphertext": "<base64>",
        "nonce":          "<base64>",
        "aes_ciphertext": "<base64>",
        "salt":           "<base64>",
        "signature":      "<base64>" | null
    }

Funciones exportadas (KEM):
    ml_kem_encrypt(plaintext, public_key_b64) -> str
    ml_kem_decrypt(token, private_key_b64)   -> str
    hqc_kem_encrypt(plaintext, public_key_b64) -> str  [condicional]
    hqc_kem_decrypt(token, private_key_b64)    -> str  [condicional]

Funciones exportadas (DSA):
    ml_dsa_sign(data_bytes, private_key_b64)                    -> str (firma b64)
    ml_dsa_verify(data_bytes, signature_b64, public_key_b64)    -> bool
    slh_dsa_sign(data_bytes, private_key_b64)                   -> str (firma b64)
    slh_dsa_verify(data_bytes, signature_b64, public_key_b64)   -> bool
"""

import os
import json
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# Importar runtime primero — asegura LD_LIBRARY_PATH y pre-carga liboqs.so
from liboqs_runtime import (
    get_oqs_module,
    resolve_kem_name,
    resolve_sig_name,
    OQS_AVAILABLE,
)
from key_manager import decode_key, encode_key


# ─────────────────────────────────────────────────────────────────────────────
#  Constantes internas
# ─────────────────────────────────────────────────────────────────────────────

_PAYLOAD_VERSION = "2.0"
_AES_KEY_LENGTH  = 32  # bytes → AES-256


# ─────────────────────────────────────────────────────────────────────────────
#  Utilidades internas
# ─────────────────────────────────────────────────────────────────────────────

def _aes_encrypt_with_key(key: bytes, plaintext_bytes: bytes) -> tuple[bytes, bytes]:
    """
    Cifra datos con AES-256-GCM usando la clave proporcionada.

    Args:
        key:             clave AES de 32 bytes (provista por KEM shared_secret)
        plaintext_bytes: datos a cifrar

    Returns:
        Tupla (nonce, ciphertext) donde:
        - nonce:      bytes aleatorios de 12 bytes (incluido en payload)
        - ciphertext: datos cifrados + tag GCM (16 bytes)
    """
    nonce      = os.urandom(12)
    aesgcm     = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return nonce, ciphertext


def _aes_decrypt_data(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Descifra datos con AES-256-GCM.

    Args:
        aes_key:    clave AES de 32 bytes (recuperada via KEM)
        nonce:      nonce de 12 bytes (del payload)
        ciphertext: datos cifrados + tag GCM

    Returns:
        Datos originales en bytes

    Raises:
        ValueError: si la clave o datos están corruptos
    """
    aesgcm = AESGCM(aes_key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Fallo al descifrar AES-GCM: clave incorrecta o datos corruptos.")


def _build_payload(
    algorithm: str,
    kem_type: str,
    kem_ciphertext: bytes,
    nonce: bytes,
    aes_ciphertext: bytes,
    signature: bytes | None = None,
    signature_type: str | None = None,
    salt: bytes | None = None,
) -> str:
    """
    Construye el payload serializado (base64 de JSON) con todos los componentes
    del cifrado híbrido.

    Args:
        algorithm:      nombre UI del algoritmo principal (e.g. "ML-KEM-768")
        kem_type:       nombre interno del KEM usado
        kem_ciphertext: ciphertext del KEM (encapsula la clave AES)
        nonce:          nonce de AES-GCM
        aes_ciphertext: datos cifrados con AES-GCM
        signature:      firma digital del payload (opcional)
        signature_type: nombre UI del algoritmo de firma (opcional)

    Returns:
        String base64 del JSON del payload completo
    """
    payload = {
        "version":        _PAYLOAD_VERSION,
        "algorithm":      algorithm,
        "kem_type":       kem_type,
        "signature_type": signature_type,
        "kem_ciphertext": base64.b64encode(kem_ciphertext).decode(),
        "nonce":          base64.b64encode(nonce).decode(),
        "aes_ciphertext": base64.b64encode(aes_ciphertext).decode(),
        "salt":           base64.b64encode(salt if salt else os.urandom(16)).decode(),
        "signature":      base64.b64encode(signature).decode() if signature else None,
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _parse_payload(token: str) -> dict:
    """
    Deserializa y valida el payload del token cifrado.

    Args:
        token: string base64 del JSON del payload

    Returns:
        Diccionario con todos los campos del payload

    Raises:
        ValueError: si el token está corrupto o incompleto
    """
    try:
        raw     = base64.b64decode(token.encode())
        payload = json.loads(raw)
    except Exception:
        raise ValueError("El token está corrupto o tiene un formato inválido (base64/JSON).")

    required = {"version", "algorithm", "kem_type", "kem_ciphertext",
                "nonce", "aes_ciphertext"}
    missing = required - set(payload.keys())
    if missing:
        raise ValueError(f"Payload incompleto. Campos faltantes: {missing}")

    return payload


# ─────────────────────────────────────────────────────────────────────────────
#  KEM — ML-KEM-768 (Kyber)
# ─────────────────────────────────────────────────────────────────────────────

def ml_kem_encrypt(plaintext: str, password: str) -> str:
    """
    Cifra texto usando KEM-DEM determinista (Flujo por Contraseña).

    Flujo:
        1. Derivar un KEM seed seguro desde la contraseña usando Scrypt.
        2. Generar el par de claves asimétrico internamente a partir del seed.
        3. Encapsular la clave AES y cifrar los datos con ella.
    """
    oqs        = get_oqs_module()
    oqs_name   = resolve_kem_name("ML-KEM-768")

    # Derivar semilla determinista desde la contraseña
    salt = os.urandom(16)
    with oqs.KeyEncapsulation(oqs_name) as kem:
        seed_length = kem.details.get("length_keypair_seed", 64)
        kdf = Scrypt(salt=salt, length=seed_length, n=2**14, r=8, p=1)
        seed = kdf.derive(password.encode("utf-8"))
        
        public_key = kem.generate_keypair_seed(seed)
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

    aes_key = shared_secret[:_AES_KEY_LENGTH]
    nonce, aes_ciphertext = _aes_encrypt_with_key(aes_key, plaintext.encode("utf-8"))

    return _build_payload(
        algorithm      = "ML-KEM-768",
        kem_type       = oqs_name,
        kem_ciphertext = kem_ciphertext,
        nonce          = nonce,
        aes_ciphertext = aes_ciphertext,
        salt           = salt
    )


def ml_kem_decrypt(token: str, password: str) -> str:
    """
    Descifra un token KEM determinista usando una contraseña.
    """
    oqs        = get_oqs_module()
    oqs_name   = resolve_kem_name("ML-KEM-768")
    payload    = _parse_payload(token)
    
    salt           = base64.b64decode(payload["salt"])
    kem_ciphertext = base64.b64decode(payload["kem_ciphertext"])
    nonce          = base64.b64decode(payload["nonce"])
    aes_ciphertext = base64.b64decode(payload["aes_ciphertext"])

    with oqs.KeyEncapsulation(oqs_name) as kem:
        seed_length = kem.details.get("length_keypair_seed", 64)
        kdf = Scrypt(salt=salt, length=seed_length, n=2**14, r=8, p=1)
        try:
            seed = kdf.derive(password.encode("utf-8"))
        except Exception:
            raise ValueError("Contraseña incorrecta.")
        
        _ = kem.generate_keypair_seed(seed)
        shared_secret = kem.decap_secret(kem_ciphertext)

    aes_key = shared_secret[:_AES_KEY_LENGTH]
    aesgcm  = AESGCM(aes_key)

    try:
        plaintext_bytes = aesgcm.decrypt(nonce, aes_ciphertext, None)
    except Exception:
        raise ValueError("Contraseña incorrecta o token corrupto.")

    return plaintext_bytes.decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
#  KEM — HQC (condicional — solo si disponible en liboqs)
# ─────────────────────────────────────────────────────────────────────────────

def hqc_kem_encrypt(plaintext: str, password: str) -> str:
    oqs        = get_oqs_module()
    oqs_name   = resolve_kem_name("HQC-KEM")
    
    salt = os.urandom(16)
    with oqs.KeyEncapsulation(oqs_name) as kem:
        seed_length = kem.details.get("length_keypair_seed", 64)
        kdf = Scrypt(salt=salt, length=seed_length, n=2**14, r=8, p=1)
        seed = kdf.derive(password.encode("utf-8"))
        
        public_key = kem.generate_keypair_seed(seed)
        kem_ciphertext, shared_secret = kem.encap_secret(public_key)

    final_aes_key = shared_secret[:_AES_KEY_LENGTH]
    nonce, aes_ciphertext = _aes_encrypt_with_key(final_aes_key, plaintext.encode("utf-8"))

    return _build_payload(
        algorithm      = "HQC-KEM",
        kem_type       = oqs_name,
        kem_ciphertext = kem_ciphertext,
        nonce          = nonce,
        aes_ciphertext = aes_ciphertext,
        salt           = salt
    )


def hqc_kem_decrypt(token: str, password: str) -> str:
    oqs      = get_oqs_module()
    oqs_name = resolve_kem_name("HQC-KEM")
    payload  = _parse_payload(token)

    salt           = base64.b64decode(payload["salt"])
    kem_ciphertext = base64.b64decode(payload["kem_ciphertext"])
    nonce          = base64.b64decode(payload["nonce"])
    aes_ciphertext = base64.b64decode(payload["aes_ciphertext"])

    with oqs.KeyEncapsulation(oqs_name) as kem:
        seed_length = kem.details.get("length_keypair_seed", 64)
        kdf = Scrypt(salt=salt, length=seed_length, n=2**14, r=8, p=1)
        try:
            seed = kdf.derive(password.encode("utf-8"))
        except Exception:
            raise ValueError("Contraseña incorrecta.")
            
        _ = kem.generate_keypair_seed(seed)
        shared_secret = kem.decap_secret(kem_ciphertext)

    final_aes_key  = shared_secret[:_AES_KEY_LENGTH]
    aesgcm         = AESGCM(final_aes_key)

    try:
        plaintext_bytes = aesgcm.decrypt(nonce, aes_ciphertext, None)
    except Exception:
        raise ValueError("Contraseña incorrecta o token corrupto.")

    return plaintext_bytes.decode("utf-8")


# ─────────────────────────────────────────────────────────────────────────────
#  DSA — ML-DSA (Dilithium nivel 3)
# ─────────────────────────────────────────────────────────────────────────────

def ml_dsa_sign(data: bytes, private_key_b64: str) -> str:
    """
    Firma datos con ML-DSA-65 (Dilithium nivel 3 NIST).

    ML-DSA es el estándar NIST FIPS 204. La variante -65 ofrece nivel de
    seguridad 3 (equivalente a AES-192) con buen balance rendimiento/tamaño.

    Args:
        data:            bytes a firmar (puede ser el payload JSON completo)
        private_key_b64: clave privada del firmante en base64 URL-safe

    Returns:
        Firma digital en base64 URL-safe

    Raises:
        RuntimeError: si liboqs no está disponible o ML-DSA no está en esta build
        ValueError: si la clave privada tiene formato inválido
    """
    oqs         = get_oqs_module()
    oqs_name    = resolve_sig_name("ML-DSA")
    private_key = decode_key(private_key_b64)

    with oqs.Signature(oqs_name, secret_key=private_key) as sig:
        signature = sig.sign(data)

    return encode_key(signature)


def ml_dsa_verify(data: bytes, signature_b64: str, public_key_b64: str) -> bool:
    """
    Verifica una firma ML-DSA-65.

    Args:
        data:           bytes que fueron firmados originalmente
        signature_b64:  firma a verificar en base64 URL-safe
        public_key_b64: clave pública del firmante en base64 URL-safe

    Returns:
        True si la firma es válida, False en caso contrario

    Raises:
        RuntimeError: si liboqs no está disponible o ML-DSA no está en esta build
        ValueError: si alguna clave o firma tiene formato inválido
    """
    oqs        = get_oqs_module()
    oqs_name   = resolve_sig_name("ML-DSA")
    public_key = decode_key(public_key_b64)
    signature  = decode_key(signature_b64)

    print(f"[DEBUG DSA Verify] Validando firma ML-DSA")
    print(f"[DEBUG DSA Verify] Longitud firma decodificada (bytes): {len(signature)}")
    print(f"[DEBUG DSA Verify] Longitud clave publica (bytes): {len(public_key)}")
    print(f"[DEBUG DSA Verify] Longitud datos: {len(data)}")

    with oqs.Signature(oqs_name) as sig:
        try:
            valid = sig.verify(data, signature, public_key)
            print(f"[DEBUG DSA Verify] Resultado sig.verify: {valid}")
            return valid
        except Exception as e:
            print(f"[DEBUG DSA Verify] Excepción en sig.verify: {e}")
            return False


# ─────────────────────────────────────────────────────────────────────────────
#  DSA — SLH-DSA (SPHINCS+ máxima seguridad conservadora)
# ─────────────────────────────────────────────────────────────────────────────

def slh_dsa_sign(data: bytes, private_key_b64: str) -> str:
    """
    Firma datos con SLH-DSA (SPHINCS+ SHA2-128S).

    SLH-DSA es el estándar NIST FIPS 205. Basado en hash trees, ofrece la
    máxima seguridad conservadora post-cuántica. La variante SHA2-128S prioriza
    tamaño pequeño de firma sobre velocidad de firma.

    Nota: La firma es más lenta que ML-DSA (~100x). Usar cuando la seguridad
    a largo plazo es prioritaria sobre el rendimiento.

    Args:
        data:            bytes a firmar
        private_key_b64: clave privada del firmante en base64 URL-safe

    Returns:
        Firma digital en base64 URL-safe

    Raises:
        RuntimeError: si liboqs no está disponible o SLH-DSA no está en esta build
        ValueError: si la clave privada tiene formato inválido
    """
    oqs         = get_oqs_module()
    oqs_name    = resolve_sig_name("SLH-DSA")
    private_key = decode_key(private_key_b64)

    with oqs.Signature(oqs_name, secret_key=private_key) as sig:
        signature = sig.sign(data)

    return encode_key(signature)


def slh_dsa_verify(data: bytes, signature_b64: str, public_key_b64: str) -> bool:
    """
    Verifica una firma SLH-DSA (SPHINCS+ SHA2-128S).

    Args:
        data:           bytes que fueron firmados originalmente
        signature_b64:  firma a verificar en base64 URL-safe
        public_key_b64: clave pública del firmante en base64 URL-safe

    Returns:
        True si la firma es válida, False en caso contrario

    Raises:
        RuntimeError: si liboqs no está disponible o SLH-DSA no está en esta build
        ValueError: si alguna clave o firma tiene formato inválido
    """
    oqs        = get_oqs_module()
    oqs_name   = resolve_sig_name("SLH-DSA")
    public_key = decode_key(public_key_b64)
    signature  = decode_key(signature_b64)
    
    print(f"[DEBUG DSA Verify] Validando marca SLH-DSA")
    print(f"[DEBUG DSA Verify] Longitud firma decodificada (bytes): {len(signature)}")
    print(f"[DEBUG DSA Verify] Longitud clave publica (bytes): {len(public_key)}")
    print(f"[DEBUG DSA Verify] Longitud datos: {len(data)}")

    with oqs.Signature(oqs_name) as sig:
        try:
            return sig.verify(data, signature, public_key)
        except Exception as e:
            print(f"[DEBUG DSA Verify] Excepción en sig.verify: {e}")
            return False
