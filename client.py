"""
====================================================
  Encrypted File Transfer & Secure File Storage
  SYNTECXHUB Internship — Project 2
  FILE: client.py
  Author: Ejikeme Ilo Cyril
====================================================

WHAT THIS FILE DOES:
  This is the SENDER side.
  It generates an AES-256 encryption key (first run only),
  encrypts your file, adds an HMAC for integrity,
  then sends the encrypted file to the server.

RUN THE SERVER FIRST, then run this file.
"""

import socket                   # built-in: network connection
import os                       # built-in: file operations
import hmac                     # built-in: message authentication
import hashlib                  # built-in: SHA-256 hashing
import json                     # built-in: sends file metadata
from Crypto.Cipher import AES           # pycryptodome: encryption
from Crypto.Util.Padding import pad     # pycryptodome: adds padding
from Crypto.Random import get_random_bytes  # pycryptodome: generates key and IV


# ─────────────────────────────────────────────
#  SETTINGS — must match server.py exactly
# ─────────────────────────────────────────────

HOST     = "127.0.0.1"     # server address (same computer)
PORT     = 9999             # must match server.py PORT
KEY_FILE = "transfer.key"  # shared key file


# ─────────────────────────────────────────────
#  GENERATE OR LOAD THE ENCRYPTION KEY
#  First run: generates a new AES-256 key and
#  saves it to transfer.key
#  Later runs: loads the existing key
# ─────────────────────────────────────────────

def get_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        print(f"[+] Loaded existing key from '{KEY_FILE}'")
    else:
        key = get_random_bytes(32)      # 32 bytes = AES-256
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        print(f"[+] Generated new AES-256 key — saved to '{KEY_FILE}'")

    return key


# ─────────────────────────────────────────────
#  ENCRYPT THE FILE
#  Reads the file from disk and encrypts it.
#
#  The final payload is structured like this:
#  [ IV — 16 bytes ] + [ HMAC — 32 bytes ] + [ Encrypted data ]
#
#  IV   = makes every encryption unique
#  HMAC = lets the server detect any tampering
# ─────────────────────────────────────────────

def encrypt_file(filepath, key):
    # Read the original file
    with open(filepath, "rb") as f:
        original_data = f.read()

    print(f"    [+] Original file size : {len(original_data)} bytes")

    # Create AES cipher — generates a random IV automatically
    cipher    = AES.new(key, AES.MODE_CBC)
    iv        = cipher.iv   # save the IV so server can decrypt

    # Encrypt (pad the data first so it fits AES block size)
    encrypted = cipher.encrypt(pad(original_data, AES.block_size))

    # Generate HMAC — a fingerprint of the encrypted data
    # Server will recalculate this to check nothing was changed
    mac = hmac.new(key, encrypted, hashlib.sha256).digest()

    # Bundle: IV + HMAC + Encrypted data
    payload = iv + mac + encrypted

    print(f"    [+] Encrypted size     : {len(payload)} bytes")
    print(f"    [+] IV   : {iv.hex()[:32]}...")
    print(f"    [+] HMAC : {mac.hex()[:32]}...")

    return payload


# ─────────────────────────────────────────────
#  SEND THE FILE TO THE SERVER
# ─────────────────────────────────────────────

def send_file(filepath, key):
    filename = os.path.basename(filepath)

    # Step 1: encrypt the file
    print(f"\n[*] Encrypting '{filename}'...")
    payload = encrypt_file(filepath, key)

    # Step 2: connect to the server
    print(f"\n[*] Connecting to server at {HOST}:{PORT}...")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((HOST, PORT))
        print("[+] Connected!")
    except ConnectionRefusedError:
        print("[!] Could not connect to server.")
        print("    Make sure server.py is running first.")
        return

    # Step 3: send filename and size as JSON metadata
    # Server needs to know what to call the file and
    # how many bytes to expect
    metadata = json.dumps({
        "filename": filename,
        "size":     len(payload)
    }).encode()

    # Send metadata length first (4 bytes), then the metadata
    client.send(len(metadata).to_bytes(4, byteorder="big"))
    client.send(metadata)

    # Step 4: send the encrypted file
    print(f"[*] Sending encrypted file...")
    client.sendall(payload)     # sendall makes sure every byte is sent

    # Step 5: wait for server response
    response = client.recv(16).decode()

    if response == "SUCCESS":
        print(f"\n[SUCCESS] '{filename}' was encrypted, transferred, and verified!")
        print(f"          Check the server's 'received_files' folder.")
    else:
        print(f"\n[FAILED] Server reported an error.")

    client.close()


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  Encrypted File Transfer — CLIENT")
    print("  SYNTECXHUB Internship — Project 2")
    print("=" * 50)

    # Generate or load the key
    key = get_or_create_key()

    # Ask which file to send
    print()
    filepath = input("Enter the name of the file to send: ").strip()

    if not os.path.exists(filepath):
        print(f"\n[!] File not found: '{filepath}'")
        print("    Make sure the file is in the same folder as client.py")
    else:
        send_file(filepath, key)