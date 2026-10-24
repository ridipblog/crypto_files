#!/usr/bin/env python3
"""
File Decryptor (Standard Library - Zero External DLL Dependencies)
Strictly decrypts files located in the project's 'files' folder (./files) ONLY.
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


def decrypt_payload(payload: bytes, key: bytes) -> bytes:
    """
    Verify integrity and decrypt payload created by encrypt_payload.
    Payload: [16-byte Nonce] + [Ciphertext] + [32-byte HMAC-SHA256]
    """
    if len(payload) < 48:
        raise ValueError("Invalid file format: payload too short to be encrypted.")

    nonce = payload[:16]
    mac = payload[-32:]
    ciphertext = payload[16:-32]

    # Verify HMAC authenticity
    expected_mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise PermissionError("Authentication failed: invalid key or corrupted file.")

    # Decrypt via keystream
    keystream = hashlib.shake_256(key + nonce).digest(len(ciphertext))
    return xor_bytes(ciphertext, keystream)


def main():
    print("=" * 65)
    print("                      FILE DECRYPTOR                          ")
    print("=" * 65)
    print("Target Location: ./files (inside project folder)")
    print("=" * 65)

    # Ensure target directory exists
    TARGET_DIR.mkdir(parents=True, exist_ok=True)

    key = get_key()

    # Collect only regular files ending with .enc inside ./files
    files = [f for f in TARGET_DIR.iterdir() if f.is_file()]
    encrypted_files = [f for f in files if f.name.endswith(".enc")]

    if not encrypted_files:
        print("\nNo encrypted (.enc) files found to decrypt in ./files.")
        print("All files are already decrypted or directory is empty.")
    else:
        print(f"\nFound {len(encrypted_files)} encrypted file(s) to decrypt in ./files:\n")
        decrypted_count = 0

        for file_path in sorted(encrypted_files, key=lambda x: x.name.lower()):
            # Enforce strict path security
            try:
                file_path.resolve().relative_to(TARGET_DIR)
            except ValueError:
                print(f"[SECURITY BLOCKED] Skipped file outside ./files: {file_path.name}")
                continue

            try:
                t0 = time.perf_counter()
                payload = file_path.read_bytes()
                plaintext = decrypt_payload(payload, key)

                # Strip .enc extension to restore original filename
                original_name = file_path.name[:-4]
                dest_path = file_path.with_name(original_name)
                dest_path.write_bytes(plaintext)

                # Remove the .enc file
                file_path.unlink()
                elapsed = time.perf_counter() - t0

                print(f"  [OK] Decrypted: {file_path.name} -> {dest_path.name} ({len(plaintext):,} bytes, {elapsed:.3f}s)")
                decrypted_count += 1
            except PermissionError as pe:
                print(f"  [FAILED] {file_path.name}: {pe}")
            except Exception as e:
                print(f"  [FAILED] Could not decrypt {file_path.name}: {e}")

        print("\n" + "-" * 65)
        print(f"Done! Successfully decrypted {decrypted_count} file(s).")
        print("-" * 65)

    print("\nCurrent files in ./files:")
    for f in sorted(TARGET_DIR.iterdir(), key=lambda x: x.name.lower()):
        if f.is_file():
            print(f"  - {f.name} ({f.stat().st_size:,} bytes)")
    print("=" * 65)


if __name__ == "__main__":
    main()
