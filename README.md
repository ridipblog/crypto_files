# File Encryptor & Decryptor CLI (`encrypt.py` / `decrypt.py`)

A secure, standalone Python tool to encrypt and decrypt files located in the project's **`./files`** folder.

Built using **100% Python Standard Library** (`hashlib`, `hmac`, `os`) with NIST SHAKE-256 stream encryption and HMAC-SHA256 authentication:
- **Zero External DLL Dependencies** (no Rust or C-extension DLL errors like `_rust.pyd`).
- **100% PyInstaller Compatible**: Compiles to lightweight, standalone `.exe` files that run on any Windows PC.

---

## 🔒 Scope & Target Directory

- **Strict Target**: Only files inside `./files` (in the project/executable folder) are modified.
- All files outside `./files` are blocked from being touched.

---

## 🚀 Usage with Python

### Encrypt all files in `./files`:
```bash
python encrypt.py
```
*Files in `./files` will be encrypted and renamed to `<filename>.enc`.*

### Decrypt all files in `./files`:
```bash
python decrypt.py
```
*Restores all `<filename>.enc` files back to their original plaintext format.*

---

## 📦 Building Silent Background `.exe` Files (No Window)

To build `.exe` files that run completely in the background with **NO black terminal window** and automatically exit when done, add the `--noconsole` (or `-w`) flag:

```bash
# 1. Build silent encrypt.exe
pyinstaller --onefile --noconsole --clean encrypt.py

# 2. Build silent decrypt.exe
pyinstaller --onefile --noconsole --clean decrypt.py
```

### How Silent Mode Works:
- When you double-click `encrypt.exe` or `decrypt.exe`, **no console window or command prompt opens**.
- It runs completely in the background, finishes the process in a fraction of a second, and terminates automatically.
- Both executables are located in the `dist\` folder (`dist\encrypt.exe` and `dist\decrypt.exe`).
