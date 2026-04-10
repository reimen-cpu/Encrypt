# Encrypt - Post-Quantum Cryptography (PQC) Suite

An advanced graphical Python application (Tkinter) that implements both classic encryption algorithms and **Hybrid Post-Quantum Cryptography (PQC)** to secure data against future quantum-computer attacks.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)
![Post-Quantum Security](https://img.shields.io/badge/Security-Post--Quantum-green.svg)

## 🌟 Key Features

1. **Professional Graphical Interface**: Adaptive dark theme with status badges, an integrated secure password generator (🎲), and seamless clipboard interactivity.
2. **Hybrid KEM Encryption via Password**: Utilizes NIST-approved algorithms (`ML-KEM-768`) hidden behind a user-friendly interface. Using a standard password, the system leverages **Scrypt** (an ultra-heavy key derivation function) to deterministically derive quantum seeds. This grants the simplicity of symmetric encryption but completely shielded by PQC KEM + AES-256-GCM.
3. **PQC Digital Signatures**: Strict authentication and integrity control using `ML-DSA` (Dilithium) or `SLH-DSA` (SPHINCS+) using formal formal public/private key pairs.
4. **Classic Algorithms Supported**: Transparent string encryption with traditional military-grade `AES-256-GCM` and `Fernet`.
5. **Portable & Packagable**: Native auto-build scripts to compile the application into a standalone executable or an isolated portable folder.

---

## ⚙️ Implemented Algorithms

| Algorithm | Type | Interface/Usage | Security Level |
| :--- | :--- | :--- | :--- |
| **AES-256-GCM** | Symmetric | Password | High (Strict NIST) |
| **ML-KEM-768** | PQC KEM | Password (KDF) | Quantum Resistant (Level 3) |
| **HQC-KEM** | PQC KEM | Password (KDF) | Quantum Resistant (Conditional) |
| **ML-DSA** | PQC Signature| Asymmetric Keys | Quantum Resistant (Balanced) |
| **SLH-DSA** | PQC Signature| Asymmetric Keys | Quantum Resistant (Ultra-Secure) |

> **Note on Signatures**: Unlike KEM flows, signature algorithms like `ML-DSA` use **mandatory asymmetric keys**. An ML-DSA public key approaches 2000 characters, and SPHINCS+ generates signatures up to 10 KB in size.

---

## 🚀 Cloning and Setup

The `Encrypt` suite requires the underlying C-library `liboqs` (Open Quantum Safe) pre-installed at the system level.

### 1. Operating System Requirement (`liboqs`)
You must compile and install `liboqs.so` into `/usr/local/lib`.
```bash
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
```

### 2. Clone the Project & Environment
Clone this repository directly from GitHub and prepare your shielded virtual environment.

```bash
git clone https://github.com/reimen-cpu/Encrypt.git
cd Encrypt

# Create isolated environment
python -m venv pqc_env
source pqc_env/bin/activate

# Install strict dependencies (cryptography and liboqs-python)
pip install -r requirements.txt
```

### 3. Execution
While inside your virtual environment:
```bash
python src/Encrypt.py
```

---

## 💎 Usage Guide

### Encrypting and Decrypting Text (Symmetric or PQC KEM)
Applies to both `AES-256-GCM` and hybrid `ML-KEM-768` operations.
1. Type or paste your message into the **Original Document / Text** field.
2. Type a password or generate one using the dice button (`🎲`).
3. Click **Encrypt**. 
4. Copy the long base64 token generated in the result text box.
5. To decrypt, verify the algorithm selector matches, paste the token, input the exact same password, and click **Decrypt**.

### Signing Documents (DSA)
1. Select `ML-DSA` or `SLH-DSA`. You will notice the interface panel change.
2. Click the central button `⚙ Generate Key Pair`. You will receive a gigantic Public Key and a Private Key. **Save them locally**.
3. Place your document or payload in **Step 1: Original Document**.
4. Click **✍ Sign**. Your massive cryptographic seal will be displayed in **Step 2**.
5. Send the Original Document (Step 1), the Signature Seal (Step 2), and your Public Key to your recipient so they can certify its origin by pressing **✔ Verify**.

---

## 📦 Packaging to Standalone / PyInstaller

The repository includes build scripts to compile the code and Python dependencies into distributable formats. Ensure your virtual environment is active before running them.

### Option A: Fully Portable Folder (Recommended)
This mode extracts all libraries (`liboqs`, `libssl`, `libcrypto`) into a single portable directory. It bypasses OS linker issues making it robust to move to architectures matching the host.

```bash
./build_onedir.sh

# The portable folder will be located in:
# ./dist/Encrypt-PQC-Portable/
```

### Option B: OneFile Executable
This mode creates a single monolithic executable file. Perfect for distributing a single file, but relies on PyInstaller's real-time temporary directory extraction which can trigger certain antivirus solutions or linker delays.

```bash
./build.sh

# The executable will be located in:
# ./dist/Encrypt-PQC
```

---
*Maintained and operated by the REIMEN-CPU cryptographic security team.*
