"""
liboqs_runtime.py
=================
Módulo de detección y validación de la librería liboqs del sistema en tiempo
de ejecución. Garantiza que Python use la librería C compilada en /usr/local/lib
y no versiones duplicadas o empaquetadas por pip.

Arquitectura objetivo:
    Python (venv)
        ↓
    liboqs-python bindings (pqc_env/site-packages)
        ↓
    liboqs.so (desde /usr/local/lib)
        ↓
    algoritmos PQC del sistema compilado

Uso:
    from liboqs_runtime import OQS_AVAILABLE, check_liboqs_runtime
    from liboqs_runtime import get_available_kems, get_available_sigs
"""

import os
import sys
import ctypes
import ctypes.util

# ─────────────────────────────────────────────────────────────────────────────
#  Paso 1: Forzar resolución de librerías del sistema ANTES de importar oqs
#  Añade /usr/local/lib al LD_LIBRARY_PATH del proceso actual para garantizar
#  que los bindings de Python encuentren liboqs.so compilado en el sistema.
# ─────────────────────────────────────────────────────────────────────────────
def _get_base_lib_path() -> str:
    """Retorna sys._MEIPASS si estamos bajo PyInstaller, de lo contrario /usr/local/lib."""
    if hasattr(sys, "_MEIPASS"):
        meipass = getattr(sys, "_MEIPASS")
        # liboqs-python internals reads OQS_INSTALL_PATH and looks in `<path>/lib/`
        os.environ["OQS_INSTALL_PATH"] = meipass
        return os.path.join(meipass, "lib")
    return "/usr/local/lib"

def _setup_library_path() -> None:
    """
    Añade la ruta base a LD_LIBRARY_PATH y carga liboqs.so explícitamente
    via ctypes para pre-resolver la librería antes de importar el binding Python.

    Esta función debe llamarse antes de cualquier `import oqs`.
    """
    base_path = _get_base_lib_path()
    current_ldpath = os.environ.get("LD_LIBRARY_PATH", "")
    paths = [p for p in current_ldpath.split(":") if p]

    if base_path not in paths:
        paths.insert(0, base_path)
        os.environ["LD_LIBRARY_PATH"] = ":".join(paths)

    # Intento de carga explícita vía ctypes para pre-registrar la librería
    # en el linker dinamico del proceso actual.
    _try_preload_liboqs(base_path)


def _try_preload_liboqs(base_path: str) -> bool:
    """
    Intenta cargar liboqs.so explícitamente con ctypes antes de que los bindings
    Python lo necesiten. Retorna True si la carga fue exitosa.
    """
    # Búsqueda en rutas del sistema / PyInstaller bundle
    candidate_paths = [
        os.path.join(base_path, "liboqs.so"),
        os.path.join(base_path, "liboqs.so.9"),
        os.path.join(base_path, "liboqs.so.0.15.0"),
        "/usr/local/lib/liboqs.so", # Fallback forzado
    ]

    for path in candidate_paths:
        if os.path.exists(path):
            try:
                ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL)
                return True
            except OSError:
                continue

    # Fallback: búsqueda vía ctypes.util
    lib_name = ctypes.util.find_library("oqs")
    if lib_name:
        try:
            ctypes.CDLL(lib_name, mode=ctypes.RTLD_GLOBAL)
            return True
        except OSError:
            pass

    return False


# ─────────────────────────────────────────────────────────────────────────────
#  Paso 2: Configurar entorno y luego importar oqs de forma controlada
# ─────────────────────────────────────────────────────────────────────────────
_setup_library_path()

OQS_AVAILABLE: bool = False
_oqs_module = None
_oqs_version: str = "N/A"
_oqs_load_error: str = ""

try:
    import oqs as _oqs_module  # type: ignore
    OQS_AVAILABLE = True
    _oqs_version = _oqs_module.oqs_version()
except ImportError as e:
    _oqs_load_error = f"liboqs Python bindings not installed: {e}"
except Exception as e:
    _oqs_load_error = f"liboqs system library not accessible: {e}"


# ─────────────────────────────────────────────────────────────────────────────
#  Mapeo: nombre UI → nombre interno liboqs
# ─────────────────────────────────────────────────────────────────────────────

# KEMs: nombre de UI → nombre exacto en liboqs
KEM_UI_TO_OQS: dict[str, str] = {
    "ML-KEM-768": "ML-KEM-768",
    "HQC-KEM":    "HQC-128",    # nombre alternativo en algunas builds
}

# SIGs: nombre UI → nombre exacto en liboqs (se selecciona el preferido)
SIG_UI_TO_OQS: dict[str, str] = {
    "ML-DSA":  "ML-DSA-65",              # Nivel 3 NIST - balance seguridad/rendimiento
    "SLH-DSA": "SLH_DSA_PURE_SHA2_128S", # Variante pequeña/rápida
}

# Nombres alternativos de HQC en distintas versiones de liboqs
_HQC_ALIASES = {"HQC-128", "HQC-192", "HQC-256", "HQC-KEM-128",
                "HQC-KEM-192", "HQC-KEM-256"}


# ─────────────────────────────────────────────────────────────────────────────
#  API Pública
# ─────────────────────────────────────────────────────────────────────────────

def check_liboqs_runtime() -> tuple[bool, str, str | None]:
    """
    Verifica el estado de carga de liboqs en tiempo de ejecución.

    Returns:
        (disponible: bool, versión: str, error: str | None)
        - disponible: True si liboqs está cargado y funcional
        - versión: string de versión de liboqs C (e.g. "0.15.0")
        - error: mensaje de error si no está disponible, None si OK
    """
    if not OQS_AVAILABLE:
        return False, "N/A", _oqs_load_error

    # Validación adicional: asegurar que los mecanismos son accesibles
    try:
        kems = _oqs_module.get_enabled_kem_mechanisms()
        sigs = _oqs_module.get_enabled_sig_mechanisms()
        if not kems or not sigs:
            return False, _oqs_version, "liboqs loaded but no mechanisms available"
    except Exception as e:
        return False, _oqs_version, f"liboqs ABI error: {e}"

    return True, _oqs_version, None


def get_available_kems() -> list[str]:
    """
    Retorna la lista de nombres UI de algoritmos KEM disponibles en esta
    instalación de liboqs. Solo incluye algoritmos que están en KEM_UI_TO_OQS
    y realmente presentes en oqs.get_enabled_kem_mechanisms().

    Returns:
        Lista de nombres UI (e.g. ["ML-KEM-768"]) — vacía si liboqs no disponible.
    """
    if not OQS_AVAILABLE:
        return []

    try:
        enabled = set(_oqs_module.get_enabled_kem_mechanisms())
    except Exception:
        return []

    available = []

    # ML-KEM-768
    if KEM_UI_TO_OQS["ML-KEM-768"] in enabled:
        available.append("ML-KEM-768")

    # HQC: verificar con todos los alias posibles
    hqc_found = any(alias in enabled for alias in _HQC_ALIASES)
    if hqc_found:
        # Actualizar el mapa con el nombre real encontrado
        for alias in _HQC_ALIASES:
            if alias in enabled:
                KEM_UI_TO_OQS["HQC-KEM"] = alias
                break
        available.append("HQC-KEM")

    return available


def get_available_sigs() -> list[str]:
    """
    Retorna la lista de nombres UI de algoritmos de firma disponibles.

    Returns:
        Lista de nombres UI (e.g. ["ML-DSA", "SLH-DSA"]) — vacía si no disponibles.
    """
    if not OQS_AVAILABLE:
        return []

    try:
        enabled = set(_oqs_module.get_enabled_sig_mechanisms())
    except Exception:
        return []

    available = []

    if SIG_UI_TO_OQS["ML-DSA"] in enabled:
        available.append("ML-DSA")

    if SIG_UI_TO_OQS["SLH-DSA"] in enabled:
        available.append("SLH-DSA")

    return available


def resolve_kem_name(ui_name: str) -> str:
    """
    Traduce nombre UI a nombre interno de liboqs para KEM.

    Args:
        ui_name: nombre visible en la UI (e.g. "ML-KEM-768")

    Returns:
        Nombre interno de liboqs (e.g. "ML-KEM-768")

    Raises:
        KeyError: si el nombre no tiene mapeo conocido
        RuntimeError: si el algoritmo no está disponible en esta build
    """
    if ui_name not in KEM_UI_TO_OQS:
        raise KeyError(f"Algoritmo KEM desconocido: {ui_name}")

    oqs_name = KEM_UI_TO_OQS[ui_name]

    if OQS_AVAILABLE:
        enabled = set(_oqs_module.get_enabled_kem_mechanisms())
        if oqs_name not in enabled:
            raise RuntimeError(
                f"Algoritmo KEM '{ui_name}' ({oqs_name}) no está disponible "
                f"en esta compilación de liboqs."
            )

    return oqs_name


def resolve_sig_name(ui_name: str) -> str:
    """
    Traduce nombre UI a nombre interno de liboqs para firmas.

    Args:
        ui_name: nombre visible en la UI (e.g. "ML-DSA")

    Returns:
        Nombre interno de liboqs (e.g. "ML-DSA-65")

    Raises:
        KeyError: si el nombre no tiene mapeo conocido
        RuntimeError: si el algoritmo no está disponible en esta build
    """
    if ui_name not in SIG_UI_TO_OQS:
        raise KeyError(f"Algoritmo DSA desconocido: {ui_name}")

    oqs_name = SIG_UI_TO_OQS[ui_name]

    if OQS_AVAILABLE:
        enabled = set(_oqs_module.get_enabled_sig_mechanisms())
        if oqs_name not in enabled:
            raise RuntimeError(
                f"Algoritmo DSA '{ui_name}' ({oqs_name}) no está disponible "
                f"en esta compilación de liboqs."
            )

    return oqs_name


def get_oqs_module():
    """
    Retorna el módulo oqs si está disponible, o lanza RuntimeError.

    Use este helper en lugar de `import oqs` directamente para garantizar
    que la verificación de disponibilidad y el enlace de librería ya se
    realizaron.
    """
    if not OQS_AVAILABLE:
        raise RuntimeError(
            f"liboqs system library not accessible. "
            f"Detalle: {_oqs_load_error}\n"
            f"Asegúrese de que el entorno virtual se ejecute con LD_LIBRARY_PATH=/usr/local/lib"
        )
    return _oqs_module
