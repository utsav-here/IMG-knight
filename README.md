# 🛡️ IMG-KNIGHT

**A simple, fully interactive command-line tool that encrypts and decrypts image files with a password — protecting your visual data from unauthorized access *and* tampering.**

No flags to memorize. No key files to lose. Just run it, answer three questions, done.

---


## ✨ Features

- **Password-based encryption** — remember a passphrase, that's your key.
- **AES-256-GCM authenticated encryption** — confidentiality *and* tamper/corruption detection in one.
- **scrypt key derivation** — memory-hard KDF, resistant to brute-force and GPU/ASIC cracking.
- **Fully interactive CLI** — run the script, answer the prompts, no command-line arguments required.
- **Batch mode** — point it at a folder instead of a single file and it processes every image (or every `.enc` file) inside automatically.
- **Smart write fallback** — if the original folder blocks writing (e.g. Windows Controlled Folder Access on `Pictures`, OneDrive sync quirks), it automatically saves into a local `IMG-KNIGHT_output` folder and tells you so.
- **No silent overwrites** — if an output filename already exists, it saves as `name_1.ext` instead of clobbering it.
- **Optional secure delete** — after a successful encryption, choose to overwrite and delete the original plaintext file so it isn't trivially recoverable with undelete tools.

---

## 🔒 How It Works

| Layer | Detail |
|---|---|
| Cipher | AES-256 in GCM mode (authenticated encryption) |
| Key derivation | scrypt (N=65536, r=8, p=1) → 256-bit key |
| Salt | 16 random bytes, unique per file |
| Nonce | 12 random bytes, unique per file |
| Tamper detection | GCM authentication tag — wrong password or modified ciphertext both fail decryption explicitly |

**Encrypted file layout:**

```
[8 bytes]  magic header
[1 byte]   format version
[16 bytes] scrypt salt
[12 bytes] AES-GCM nonce
[N bytes]  ciphertext (encrypted metadata + image bytes, includes auth tag)
```

The original filename is stored *inside* the encrypted payload, so decrypting automatically restores it — you don't have to remember what `IMG_4821.jpg.enc` used to be called.

---

## 📦 Installation

```bash
git clone https://github.com/<your-username>/img-knight.git
cd img-knight
pip install cryptography
```

That's the only dependency.

---

## 🚀 Usage

```bash
python img_knight.py
```

You'll be walked through everything:

```
============================================
   IMG-KNIGHT - Image Encryption Guardian
============================================

Enter the image/file path: photo.jpg
Encrypt or Decrypt? (E/D): E
Enter password: ********
Confirm password: ********
  OK  photo.jpg -> photo.jpg.enc

SUCCESS: Encrypted 1 file(s).

Note: the original unencrypted file(s) are still on disk.
Securely delete the original(s) now? This cannot be undone -- make sure you remember your password. (y/N): n
Originals kept. Delete them yourself once you've confirmed decryption works.
```

Decrypting works the same way — point it at the `.enc` file and enter the password:

```
Enter the image/file path: photo.jpg.enc
Encrypt or Decrypt? (E/D): D
Enter password: ********
  OK  photo.jpg.enc -> photo.jpg

SUCCESS: Decrypted 1 file(s).
```

**Batch mode** — point it at a folder instead of a file, and it finds everything eligible inside automatically (images for encrypt, `.enc` files for decrypt).

---

## ⚠️ Security Notes

- There is no password recovery or backdoor. **If you forget the password, the file cannot be decrypted — ever.**
- Secure delete performs a best-effort single-pass overwrite before deletion. On SSDs, wear-leveled drives, journaling filesystems, and cloud-synced folders, this does **not** guarantee the original bytes are unrecoverable, due to how those storage layers actually write data. For genuinely sensitive material, pair this with full-disk encryption.
- This is a personal/educational project, not an audited security product. For high-stakes use cases, prefer established, independently reviewed tools.

---

## 🗂 Project Structure

```
img-knight/
└── img_knight.py   # the entire tool — single file, one dependency
```

---

## 🛣️ Roadmap

- [ ] Optional key-file based encryption (instead of password-only)
- [ ] Cross-platform GUI (drag & drop)
- [ ] Configurable scrypt cost parameters via prompt

---

## 🤝 Contributing

Contributions are welcome. Fork the repo, create a feature branch, and open a pull request.

---
