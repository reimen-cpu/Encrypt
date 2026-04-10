#!/bin/bash

# Detener ejecución si hay un error
set -e

echo "================================================="
echo "   Compilador PyInstaller para Encrypt PQC       "
echo "================================================="

# Verificar si estamos en el entorno virtual
if [ -z "$VIRTUAL_ENV" ]; then
    echo "⚠️ ADVERTENCIA: No estás en tu entorno virtual."
    echo "Si ves que fallan librerías, cancela (Ctrl+C) y ejecuta primero:"
    echo "   source pqc_env/bin/activate"
    echo ""
    sleep 3
fi

# Instalar PyInstaller si no está presente en el entorno
if ! python3 -m PyInstaller --version &> /dev/null; then
    echo "⚙️  Instalando PyInstaller localmente..."
    python3 -m pip install pyinstaller
fi

echo "🚀 Iniciando proceso de compilación (OneFile Mode)..."

# Limpiar compilaciones previas
rm -rf build/ dist/ Encrypt-PQC.spec

# Opciones de PyInstaller:
# --noconfirm : Sobrescribir salida sin preguntar
# --onefile   : Empaquetar todo en un único ejecutable
# --windowed  : No mostrar consola (app gráfica pura Tkinter)
# --add-binary: Incluir liboqs.so en el subdirectorio /lib secreto de PyInstaller
python3 -m PyInstaller --noconfirm \
    --onefile \
    --windowed \
    --name "Encrypt-PQC" \
    --hidden-import "oqs" \
    --hidden-import "cryptography" \
    --add-binary "/usr/local/lib/liboqs.so:lib" \
    src/Encrypt.py

echo "================================================="
echo "✅ ¡Compilación Completada Exitosamente!"
echo "📂 El ejecutable final está en: ./dist/Encrypt-PQC"
echo "================================================="
