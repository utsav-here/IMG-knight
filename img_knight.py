#!/usr/bin/env python3
"""
IMG-KNIGHT
Interactive image encryption/decryption tool, secured with AES-256-GCM
authenticated encryption (tampering/corruption is detected automatically)
and a scrypt-derived password key.

Run:  python img_knight.py
"""

import getpass
import json
import os
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"IMGKNGT1"
FORMAT_VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".tiff", ".tif", ".heic", ".heif", ".raw", ".svg",
}
ENCRYPTED_EXTENSION = ".enc"


class ImgKnightError(Exception):
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str, original_filename: str) -> bytes:
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    metadata = json.dumps({"filename": original_filename}).encode("utf-8")
    payload = struct.pack(">I", len(metadata)) + metadata + data
    ciphertext = AESGCM(key).encrypt(nonce, payload, associated_data=MAGIC)
    return MAGIC + bytes([FORMAT_VERSION]) + salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str):
    header_len = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
    if len(blob) < header_len or blob[:len(MAGIC)] != MAGIC or blob[len(MAGIC)] != FORMAT_VERSION:
        raise ImgKnightError("This doesn't look like a valid IMG-KNIGHT encrypted file.")

    offset = len(MAGIC) + 1
    salt = blob[offset:offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = blob[offset:offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = blob[offset:]

    key = derive_key(password, salt)
    try:
        payload = AESGCM(key).decrypt(nonce, ciphertext, associated_data=MAGIC)
    except InvalidTag:
        raise ImgKnightError("Wrong password, or the file has been corrupted/tampered with.")

    meta_len = struct.unpack(">I", payload[:4])[0]
    metadata = json.loads(payload[4:4 + meta_len].decode("utf-8"))
    return payload[4 + meta_len:], metadata.get("filename", "decrypted_image")


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem, suffix, parent = path.stem, path.suffix, path.parent
    i = 1
    while True:
        candidate = parent / f"{stem}_{i}{suffix}"
        if not candidate.exists():
            return candidate
        i += 1


def secure_delete(path: Path) -> None:
    """Overwrite the file's bytes with random data before deleting it, so
    the original plaintext isn't trivially recoverable with undelete tools."""
    try:
        length = path.stat().st_size
        with open(path, "r+b") as f:
            f.seek(0)
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass  # if overwrite isn't possible, still try a normal delete below
    path.unlink()


def get_password(confirm: bool) -> str:
    pw = getpass.getpass("Enter password: ")
    if not pw:
        raise ImgKnightError("Password cannot be empty.")
    if confirm:
        pw2 = getpass.getpass("Confirm password: ")
        if pw != pw2:
            raise ImgKnightError("Passwords didn't match.")
    return pw


FALLBACK_DIR_NAME = "IMG-KNIGHT_output"


def safe_write(preferred_path: Path, data: bytes) -> Path:
    """
    Write to preferred_path. If that fails (e.g. OneDrive sync lock,
    Windows Controlled Folder Access blocking writes to Pictures/Desktop,
    a read-only/missing folder, etc.), fall back to a folder next to the
    script instead of crashing.
    """
    try:
        preferred_path.parent.mkdir(parents=True, exist_ok=True)
        preferred_path.write_bytes(data)
        return preferred_path
    except OSError as e:
        fallback_dir = Path.cwd() / FALLBACK_DIR_NAME
        fallback_dir.mkdir(parents=True, exist_ok=True)
        fallback_path = unique_path(fallback_dir / preferred_path.name)
        fallback_path.write_bytes(data)
        print(f"  ! Could not write to original folder ({e.strerror or e}).")
        print(f"  ! Saved here instead: {fallback_path}")
        return fallback_path


def encrypt_one(path: Path, password: str) -> Path:
    data = path.read_bytes()
    blob = encrypt_bytes(data, password, path.name)
    out = unique_path(path.with_suffix(path.suffix + ENCRYPTED_EXTENSION))
    return safe_write(out, blob)


def decrypt_one(path: Path, password: str) -> Path:
    blob = path.read_bytes()
    image_data, original_name = decrypt_bytes(blob, password)
    out = unique_path(path.parent / original_name)
    return safe_write(out, image_data)


def banner():
    print()
    print("=" * 44)
    print("   IMG-KNIGHT - Image Encryption Guardian")
    print("=" * 44)
    print()


def run():
    banner()

    raw_path = input("Enter the image/file path: ").strip().strip('"').strip("'")
    if not raw_path:
        print("No path entered. Exiting.")
        sys.exit(1)
    path = Path(raw_path).expanduser()
    if not path.exists():
        print(f"X Path not found: {path}")
        sys.exit(1)

    while True:
        choice = input("Encrypt or Decrypt? (E/D): ").strip().lower()
        if choice in ("e", "encrypt"):
            mode = "encrypt"
            break
        if choice in ("d", "decrypt"):
            mode = "decrypt"
            break
        print("Please type E (encrypt) or D (decrypt).")

    if path.is_dir():
        if mode == "encrypt":
            targets = sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS)
        else:
            targets = sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() == ENCRYPTED_EXTENSION)
        if not targets:
            wanted = "image" if mode == "encrypt" else ENCRYPTED_EXTENSION
            print(f"X No {wanted} files found in that folder.")
            sys.exit(1)
        print(f"Found {len(targets)} file(s) to {mode}.")
    else:
        targets = [path]

    try:
        password = get_password(confirm=(mode == "encrypt"))
    except ImgKnightError as e:
        print(f"X {e}")
        sys.exit(1)

    ok, failed = 0, 0
    succeeded = []
    for t in targets:
        try:
            out = encrypt_one(t, password) if mode == "encrypt" else decrypt_one(t, password)
            print(f"  OK  {t.name} -> {out.name}")
            ok += 1
            succeeded.append(t)
        except ImgKnightError as e:
            print(f"  FAIL  {t.name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  FAIL  {t.name}: unexpected error: {e}")
            failed += 1

    print()
    if failed == 0:
        verb = "Encrypted" if mode == "encrypt" else "Decrypted"
        print(f"SUCCESS: {verb} {ok} file(s).")

        if mode == "encrypt" and succeeded:
            print()
            print("Note: the original unencrypted file(s) are still on disk.")
            answer = input(
                "Securely delete the original(s) now? This cannot be undone "
                "-- make sure you remember your password. (y/N): "
            ).strip().lower()
            if answer == "y":
                deleted = 0
                for t in succeeded:
                    try:
                        secure_delete(t)
                        print(f"  Deleted: {t.name}")
                        deleted += 1
                    except OSError as e:
                        print(f"  ! Could not delete {t.name}: {e}")
                print(f"Deleted {deleted}/{len(succeeded)} original file(s).")
            else:
                print("Originals kept. Delete them yourself once you've confirmed decryption works.")

        sys.exit(0)
    else:
        print(f"DONE WITH ERRORS: {ok} succeeded, {failed} failed.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)