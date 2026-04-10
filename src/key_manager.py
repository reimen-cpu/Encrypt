"""
key_manager.py
==============
Gestión de pares de claves post-cuánticas (PQC) para algoritmos KEM y DSA.

Este módulo provee funciones para generar, serializar y deserializar pares de
claves PQC usando liboqs. Las claves se representan externamente como strings
base64 URL-safe para facilitar su almacenamiento y transmisión.

Dependencias:
    - liboqs_runtime (debe ser importado primero para garantizar enlace)
    - oqs (instalado en pqc_env, enlazado a /usr/local/lib/liboqs.so)

Funciones exportadas:
    generate_kem_keypair(ui_algorithm)  -> (pub_b64, priv_b64)
    generate_sig_keypair(ui_algorithm)  -> (pub_b64, priv_b64)
    decode_key(key_b64)                 -> bytes
    encode_key(key_bytes)               -> str
"""

import base64

# Importar runtime primero — asegura LD_LIBRARY_PATH y pre-carga liboqs.so
from liboqs_runtime import (
    get_oqs_module,
    resolve_kem_name,
    resolve_sig_name,
    OQS_AVAILABLE,
)


# ─────────────────────────────────────────────────────────────────────────────
#  Utilidades de serialización
# ─────────────────────────────────────────────────────────────────────────────

def encode_key(key_bytes: bytes) -> str:
    """
    Serializa bytes de clave a string base64 URL-safe.

    Args:
        key_bytes: bytes crudos de la clave (public key o private key)

    Returns:
        String base64 URL-safe sin padding (para uso en UI y JSON)
    """
    return base64.urlsafe_b64encode(key_bytes).decode("ascii")


def decode_key(key_b64: str) -> bytes:
    """
    Deserializa un string base64 URL-safe a bytes de clave.

    Maneja tanto base64 con padding como sin padding.

    Args:
        key_b64: string base64 URL-safe (con o sin '=' de padding)

    Returns:
        bytes de la clave

    Raises:
        ValueError: si el string no es base64 válido
    """
    # Eliminar posibles espacios en blanco o saltos de línea (ej. por copy-paste)
    key_b64 = "".join(key_b64.split())

    # Añadir padding si es necesario
    padding_needed = len(key_b64) % 4
    if padding_needed:
        key_b64 += "=" * (4 - padding_needed)
    try:
        return base64.urlsafe_b64decode(key_b64)
    except Exception as e:
        raise ValueError(f"Clave en formato base64 inválido: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  Generación de pares de claves KEM
# ─────────────────────────────────────────────────────────────────────────────

def generate_kem_keypair(ui_algorithm: str) -> tuple[str, str]:
    """
    Genera un par de claves para el algoritmo KEM especificado.

    El par de claves es efímero por defecto — si necesitas persistencia,
    guarda los strings base64 retornados en un lugar seguro.

    Args:
        ui_algorithm: nombre UI del algoritmo (e.g. "ML-KEM-768", "HQC-KEM")

    Returns:
        Tupla (public_key_b64, private_key_b64) en base64 URL-safe.
        - public_key_b64:  usar para cifrar (compartir con remitente)
        - private_key_b64: usar para descifrar (MANTENER SECRETO)

    Raises:
        RuntimeError: si liboqs no está disponible
        KeyError: si el algoritmo no existe en el mapeo
        RuntimeError: si el algoritmo no está disponible en esta build de liboqs
    """
    oqs = get_oqs_module()
    oqs_name = resolve_kem_name(ui_algorithm)

    with oqs.KeyEncapsulation(oqs_name) as kem:
        public_key  = kem.generate_keypair()
        private_key = kem.export_secret_key()

    return encode_key(public_key), encode_key(private_key)


# ─────────────────────────────────────────────────────────────────────────────
#  Generación de pares de claves DSA (firmas digitales)
# ─────────────────────────────────────────────────────────────────────────────

def generate_sig_keypair(ui_algorithm: str) -> tuple[str, str]:
    """
    Genera un par de claves para el algoritmo de firma especificado.

    Args:
        ui_algorithm: nombre UI del algoritmo (e.g. "ML-DSA", "SLH-DSA")

    Returns:
        Tupla (public_key_b64, private_key_b64) en base64 URL-safe.
        - public_key_b64:  usar para verificar firmas (compartir)
        - private_key_b64: usar para firmar (MANTENER SECRETO)

    Raises:
        RuntimeError: si liboqs no está disponible
        KeyError: si el algoritmo no existe en el mapeo
        RuntimeError: si el algoritmo no está disponible en esta build de liboqs
    """
    oqs = get_oqs_module()
    oqs_name = resolve_sig_name(ui_algorithm)

    with oqs.Signature(oqs_name) as sig:
        public_key  = sig.generate_keypair()
        private_key = sig.export_secret_key()

    return encode_key(public_key), encode_key(private_key)


# ─────────────────────────────────────────────────────────────────────────────
#  Información de algoritmos
# ─────────────────────────────────────────────────────────────────────────────

def get_kem_info(ui_algorithm: str) -> dict:
    """
    Retorna información técnica del algoritmo KEM: tamaños de clave,
    ciphertext, etc.

    Args:
        ui_algorithm: nombre UI del algoritmo

    Returns:
        Diccionario con campos: name, claimed_nist_level, length_public_key,
        length_secret_key, length_ciphertext, length_shared_secret
    """
    oqs = get_oqs_module()
    oqs_name = resolve_kem_name(ui_algorithm)

    with oqs.KeyEncapsulation(oqs_name) as kem:
        return {
            "name":                 kem.alg_name,
            "claimed_nist_level":   kem.claimed_nist_level,
            "length_public_key":    kem.length_public_key,
            "length_secret_key":    kem.length_secret_key,
            "length_ciphertext":    kem.length_ciphertext,
            "length_shared_secret": kem.length_shared_secret,
        }


def get_sig_info(ui_algorithm: str) -> dict:
    """
    Retorna información técnica del algoritmo de firma.

    Args:
        ui_algorithm: nombre UI del algoritmo

    Returns:
        Diccionario con campos: name, claimed_nist_level, length_public_key,
        length_secret_key, length_signature, max_length_signature
    """
    oqs = get_oqs_module()
    oqs_name = resolve_sig_name(ui_algorithm)

    with oqs.Signature(oqs_name) as sig:
        return {
            "name":                 sig.alg_name,
            "claimed_nist_level":  sig.claimed_nist_level,
            "length_public_key":   sig.length_public_key,
            "length_secret_key":   sig.length_secret_key,
            "max_length_signature": sig.max_length_signature,
        }
