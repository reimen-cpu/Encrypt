#!/bin/bash

# Stop execution if an error occurs
set -e

echo "================================================="
echo "   PyInstaller Compiler (OneDir) - Encrypt PQC   "
echo "================================================="

# Check if inside virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    echo "⚠️ WARNING: You are not inside a virtual environment."
    echo "Please cancel (Ctrl+C) and run:"
    echo "   source pqc_env/bin/activate"
    echo ""
    sleep 3
fi

# Install PyInstaller
if ! python3 -m PyInstaller --version &> /dev/null; then
    echo "⚙️  Installing PyInstaller locally..."
    python3 -m pip install pyinstaller
fi

echo "🚀 Starting compilation (OneDir Mode)..."

rm -rf build/ dist/ Encrypt-PQC-Portable.spec

# Find runtime dependencies natively on the system to bundle them
CRYPTO_LIB=$(ldconfig -p | grep libcrypto.so.3 | head -n 1 | tr -d ' ' | cut -d'>' -f2)
SSL_LIB=$(ldconfig -p | grep libssl.so.3 | head -n 1 | tr -d ' ' | cut -d'>' -f2)

BINARIES="--add-binary /usr/local/lib/liboqs.so:lib"

if [ -n "$CRYPTO_LIB" ] && [ -f "$CRYPTO_LIB" ]; then
    echo "📦 Bundling $CRYPTO_LIB"
    BINARIES="$BINARIES --add-binary $CRYPTO_LIB:lib"
fi

if [ -n "$SSL_LIB" ] && [ -f "$SSL_LIB" ]; then
    echo "📦 Bundling $SSL_LIB"
    BINARIES="$BINARIES --add-binary $SSL_LIB:lib"
fi

# PyInstaller Options
# --onedir  : Extract into a portable folder structure instead of a single file
# --windowed: No console, pure GUI
python3 -m PyInstaller --noconfirm \
    --onedir \
    --windowed \
    --name "Encrypt-PQC-Portable" \
    --hidden-import "oqs" \
    --hidden-import "cryptography" \
    $BINARIES \
    src/Encrypt.py

echo "================================================="
echo "✅ Compilation Successfully Completed!"
echo "📂 Your portable directory is located at: ./dist/Encrypt-PQC-Portable"
echo "================================================="
