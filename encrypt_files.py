#!/usr/bin/env python3
"""
File Encryption CLI
Strictly encrypts and decrypts files located in the project's 'files' folder (./files) only.
Uses authenticated AES-128-CBC + HMAC-SHA256 (Fernet) encryption.
"""

import argparse
import base64
import hashlib
import os
import sys
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("Error: The 'cryptography' library is required.")
    print("Install it with: pip install cryptography")
    sys.exit(1)

# STRICT TARGET DIRECTORY: Only files within this directory can be touched!
BASE_DIR = Path(__file__).resolve().parent
TARGET_DIR = (BASE_DIR / "files").resolve()
KEY_FILE = BASE_DIR / "secret.key"
MAGIC_HEADER = b"FERNET_ENC_V1::"


def verify_target_directory() -> Path:
    """Ensure the target directory exists and return its resolved Path."""
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    return TARGET_DIR


def assert_within_target_dir(file_path: Path):
    """Enforce strict isolation: prevent path traversal or access outside TARGET_DIR."""
    resolved = file_path.resolve()
    try:
        resolved.relative_to(TARGET_DIR)
    except ValueError:
        raise PermissionError(
            f"SECURITY ERROR: '{file_path}' is outside the allowed directory '{TARGET_DIR}'."
        )


def get_or_create_key(key_file: Path = KEY_FILE) -> bytes:
    """Load the encryption key from file, or generate a new one if not present."""
    if key_file.exists():
        key = key_file.read_bytes().strip()
        if len(key) > 0:
            return key

    key = Fernet.generate_key()
    key_file.write_bytes(key)
    print(f"[KEY GENERATED] New encryption key saved to: {key_file.name}")
    return key


def derive_key_from_password(password: str, salt_file: Path) -> bytes:
    """Derive a Fernet-compatible 32-byte urlsafe base64 key from a password using PBKDF2."""
    if salt_file.exists():
        salt = salt_file.read_bytes()
    else:
        salt = os.urandom(16)
        salt_file.write_bytes(salt)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    derived = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


def is_file_encrypted(file_path: Path) -> bool:
    """Determine whether a file is already encrypted."""
    if file_path.suffix == ".enc":
        return True
    try:
        with file_path.open("rb") as f:
            header = f.read(len(MAGIC_HEADER))
            return header == MAGIC_HEADER
    except (OSError, PermissionError):
        return False


def encrypt_single_file(
    file_path: Path,
    fernet: Fernet,
    in_place: bool = False,
    keep_original: bool = False,
) -> Path | None:
    """
    Encrypt a single file inside TARGET_DIR.
    Returns the path to the encrypted file.
    """
    assert_within_target_dir(file_path)

    if not file_path.is_file():
        return None

    if is_file_encrypted(file_path):
        print(f"  [SKIPPED] Already encrypted: {file_path.name}")
        return None

    data = file_path.read_bytes()
    ciphertext = fernet.encrypt(data)

    if in_place:
        # Save in-place with magic header to identify encrypted status
        payload = MAGIC_HEADER + ciphertext
        file_path.write_bytes(payload)
        dest_path = file_path
        print(f"  [ENCRYPTED IN-PLACE] {file_path.name} ({len(data)} bytes -> {len(payload)} bytes)")
    else:
        # Save as filename.enc
        dest_path = file_path.with_name(file_path.name + ".enc")
        dest_path.write_bytes(ciphertext)
        if not keep_original:
            file_path.unlink()
        print(f"  [ENCRYPTED] {file_path.name} -> {dest_path.name} ({len(data)} bytes -> {len(ciphertext)} bytes)")

    return dest_path


def decrypt_single_file(
    file_path: Path,
    fernet: Fernet,
    keep_original: bool = False,
) -> Path | None:
    """
    Decrypt a single file inside TARGET_DIR.
    Returns the path to the decrypted file.
    """
    assert_within_target_dir(file_path)

    if not file_path.is_file():
        return None

    if not is_file_encrypted(file_path):
        print(f"  [SKIPPED] File is not encrypted: {file_path.name}")
        return None

    data = file_path.read_bytes()

    # Check if in-place header exists
    if data.startswith(MAGIC_HEADER):
        ciphertext = data[len(MAGIC_HEADER):]
        try:
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken:
            print(f"  [ERROR] Decryption failed (invalid key or corrupted data): {file_path.name}")
            return None

        file_path.write_bytes(plaintext)
        print(f"  [DECRYPTED IN-PLACE] {file_path.name} ({len(data)} bytes -> {len(plaintext)} bytes)")
        return file_path

    # Otherwise, file was encrypted with .enc extension
    try:
        plaintext = fernet.decrypt(data)
    except InvalidToken:
        print(f"  [ERROR] Decryption failed (invalid key or corrupted data): {file_path.name}")
        return None

    # Strip .enc extension
    if file_path.name.endswith(".enc"):
        dest_name = file_path.name[:-4]
    else:
        dest_name = file_path.name + ".dec"

    dest_path = file_path.with_name(dest_name)
    dest_path.write_bytes(plaintext)
    if not keep_original:
        file_path.unlink()

    print(f"  [DECRYPTED] {file_path.name} -> {dest_path.name} ({len(data)} bytes -> {len(plaintext)} bytes)")
    return dest_path


def show_status(target_dir: Path):
    """Show the encryption status of all files in the target directory."""
    files = [p for p in target_dir.iterdir() if p.is_file()]
    print(f"\nTarget Location: {target_dir}")
    print(f"Total Files:     {len(files)}")
    print("-" * 65)
    print(f"{'Filename':<35} {'Size (Bytes)':<15} {'Status':<15}")
    print("-" * 65)

    if not files:
        print("  (Directory is empty)")
    else:
        for f in sorted(files, key=lambda x: x.name.lower()):
            size = f.stat().st_size
            enc = is_file_encrypted(f)
            status_str = "Encrypted" if enc else "Plaintext"
            print(f"{f.name:<35} {size:<15,} {status_str:<15}")
    print("-" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt/Decrypt files strictly inside the project's 'files' folder (./files)"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--encrypt",
        "-e",
        action="store_true",
        help="Encrypt all plaintext files in the files folder (default action).",
    )
    group.add_argument(
        "--decrypt",
        "-d",
        action="store_true",
        help="Decrypt all encrypted files in the files folder.",
    )
    group.add_argument(
        "--status",
        "-s",
        action="store_true",
        help="Show encryption status of files in the files folder.",
    )

    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Encrypt in-place without renaming to .enc extension.",
    )
    parser.add_argument(
        "--keep-original",
        action="store_true",
        help="Keep original file when encrypting/decrypting with extension change.",
    )
    parser.add_argument(
        "--key",
        type=str,
        help="Provide a base64 Fernet encryption key string.",
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        default=KEY_FILE,
        help=f"Path to secret key file (defaults to {KEY_FILE.name}).",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Derive encryption key from a password.",
    )

    args = parser.parse_args()
    target_dir = verify_target_directory()

    # Determine encryption key
    if args.password:
        salt_file = BASE_DIR / "salt.bin"
        key = derive_key_from_password(args.password, salt_file)
    elif args.key:
        key = args.key.encode("utf-8")
    else:
        key = get_or_create_key(args.key_file)

    try:
        fernet = Fernet(key)
    except Exception as e:
        print(f"Error: Invalid encryption key: {e}")
        sys.exit(1)

    print("=" * 65)
    print("      FILE ENCRYPTION CLI - TARGET: files/ DIRECTORY ONLY      ")
    print("=" * 65)
    print(f"Target Directory: {target_dir}")
    print(f"Key Source:       {'Password derived' if args.password else ('CLI key' if args.key else args.key_file.name)}")
    print("=" * 65)

    if args.status:
        show_status(target_dir)
        return

    # Check if directory is empty
    target_files = [p for p in target_dir.iterdir() if p.is_file()]
    if not target_files:
        print(f"\nNo files found in {target_dir}.")
        return

    if args.decrypt:
        print("\n[ACTION: DECRYPTING FILES]")
        count = 0
        for f in sorted(target_files, key=lambda x: x.name):
            if is_file_encrypted(f):
                res = decrypt_single_file(f, fernet, keep_original=args.keep_original)
                if res:
                    count += 1
        print(f"\nDone. Successfully decrypted {count} file(s).")
    else:
        # Default action: Encrypt
        print("\n[ACTION: ENCRYPTING FILES]")
        count = 0
        for f in sorted(target_files, key=lambda x: x.name):
            if not is_file_encrypted(f):
                res = encrypt_single_file(
                    f,
                    fernet,
                    in_place=args.in_place,
                    keep_original=args.keep_original,
                )
                if res:
                    count += 1
        print(f"\nDone. Successfully encrypted {count} file(s).")

    show_status(target_dir)


if __name__ == "__main__":
    main()
