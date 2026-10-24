#!/usr/bin/env python3
"""
File Encryptor (Standard Library - Zero External DLL Dependencies)
Strictly encrypts files located in the project's 'files' folder (./files) ONLY.
Uses NIST SHAKE-256 stream encryption + HMAC-SHA256 authentication.
100% compatible with PyInstaller --onefile (Zero DLL errors).
"""

import hashlib
import hmac
import os
import sys
import time
from pathlib import Path

# ----------------------------------------------------------------------
# SHARED SECRET KEY (Identical in both encrypt.py and decrypt.py)
# ----------------------------------------------------------------------
DEFAULT_KEY = b"Tkw5Bs8t2ZyAhaQGrGzLrbVKeG-j4h_Dg2I8E5hsri8="

# Determine project directory (compatible with PyInstaller onefile .exe)
# Determine project and target directory (compatible with PyInstaller onefile .exe)
if getattr(sys, "frozen", False):
    exe_dir = Path(sys.executable).resolve().parent
    if (exe_dir / "files").exists():
        TARGET_DIR = (exe_dir / "files").resolve()
        PROJECT_DIR = exe_dir
    elif (Path.cwd() / "files").exists():
        TARGET_DIR = (Path.cwd() / "files").resolve()
        PROJECT_DIR = Path.cwd().resolve()
    elif (exe_dir.parent / "files").exists():
        TARGET_DIR = (exe_dir.parent / "files").resolve()
        PROJECT_DIR = exe_dir.parent.resolve()
    else:
        TARGET_DIR = (exe_dir / "files").resolve()
        PROJECT_DIR = exe_dir
else:
    PROJECT_DIR = Path(__file__).resolve().parent
    TARGET_DIR = (PROJECT_DIR / "files").resolve()

KEY_FILE = PROJECT_DIR / "secret.key"


def get_key() -> bytes:
    """Load key from secret.key file if present, otherwise use DEFAULT_KEY."""
    if KEY_FILE.exists():
        try:
            file_key = KEY_FILE.read_bytes().strip()
            if len(file_key) >= 16:
                return file_key
        except Exception:
            pass
    return DEFAULT_KEY


def xor_bytes(data: bytes, keystream: bytes) -> bytes:
    """Fast XOR combining data and keystream in 64KB chunks."""
    chunk_size = 65536
    res = bytearray(len(data))
    for i in range(0, len(data), chunk_size):
        end = min(i + chunk_size, len(data))
        d = int.from_bytes(data[i:end], "little")
        k = int.from_bytes(keystream[i:end], "little")
        res[i:end] = (d ^ k).to_bytes(end - i, "little")
    return bytes(res)


def encrypt_payload(data: bytes, key: bytes) -> bytes:
    """
    Encrypt data using NIST SHAKE-256 stream cipher with HMAC-SHA256 integrity tag.
    Format: [16-byte Nonce] + [Ciphertext] + [32-byte HMAC-SHA256]
    """
    nonce = os.urandom(16)
    keystream = hashlib.shake_256(key + nonce).digest(len(data))
    ciphertext = xor_bytes(data, keystream)
    mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + mac


def main():
    print("=" * 65)
    print("                      FILE ENCRYPTOR                          ")
    print("=" * 65)

    # Ensure target directory exists
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    key = get_key()

    # Collect only regular files inside ./files that are not already .enc
    files = [f for f in TARGET_DIR.iterdir() if f.is_file()]
    plaintext_files = [f for f in files if not f.name.endswith(".enc")]

    if not plaintext_files:
        print("\nNo unencrypted files found to encrypt in ./files.")
        print("All files are already encrypted (.enc) or directory is empty.")
    else:
        print(f"\nFound {len(plaintext_files)} file(s) to encrypt in ./files:\n")
        encrypted_count = 0

        for file_path in sorted(plaintext_files, key=lambda x: x.name.lower()):
            # Enforce strict path security
            try:
                file_path.resolve().relative_to(TARGET_DIR)
            except ValueError:
                print(f"[SECURITY BLOCKED] Skipped file outside ./files: {file_path.name}")
                continue

            try:
                t0 = time.perf_counter()
                original_size = file_path.stat().st_size
                data = file_path.read_bytes()
                encrypted_data = encrypt_payload(data, key)

                dest_path = file_path.with_name(file_path.name + ".enc")
                dest_path.write_bytes(encrypted_data)

                # Remove original plaintext file
                file_path.unlink()
                elapsed = time.perf_counter() - t0

                print(f"  [OK] Encrypted: {file_path.name} -> {dest_path.name} ({original_size:,} bytes, {elapsed:.3f}s)")
                encrypted_count += 1
            except Exception as e:
                print(f"  [FAILED] Could not encrypt {file_path.name}: {e}")

        print("\n" + "-" * 65)
        print(f"Done! Successfully encrypted {encrypted_count} file(s).")
        print("-" * 65)

    print("\nCurrent files in ./files:")
    for f in sorted(TARGET_DIR.iterdir(), key=lambda x: x.name.lower()):
        if f.is_file():
            print(f"  - {f.name} ({f.stat().st_size:,} bytes)")
    print("=" * 65)


if __name__ == "__main__":
    main()
