"""
====================================================
  Encrypted File Transfer & Secure File Storage
  SYNTECXHUB Internship — Project 2
  FILE: server.py
  Author: Ejikeme Ilo Cyril
====================================================

WHAT THIS FILE DOES:
  This is the RECEIVER side.
  It listens for incoming encrypted files,
  verifies they haven't been tampered with (HMAC),
  decrypts them using AES-256, and saves them to disk.

RUN THIS FIRST before running client.py
"""

import socket               # built-in: handles network connections
import os                   # built-in: folder and file operations
import hmac                 # built-in: verifies file integrity
import hashlib              # built-in: SHA-256 hashing
import json                 # built-in: receives file metadata
from Crypto.Cipher import AES           # pycryptodome: decryption
from Crypto.Util.Padding import unpad   # pycryptodome: removes padding


# ─────────────────────────────────────────────
#  SETTINGS
# ─────────────────────────────────────────────

HOST        = "127.0.0.1"       # server runs on this computer
PORT        = 9999              # port to listen on
KEY_FILE    = "transfer.key"    # shared secret key (created by client)
SAVE_FOLDER = "received_files"  # folder where received files are saved


# ─────────────────────────────────────────────
#  LOAD THE SHARED KEY
#  Both server and client must use the same key.
#  The client creates it on first run.
# ─────────────────────────────────────────────

def load_key():
    if not os.path.exists(KEY_FILE):
        print(f"[!] Key file '{KEY_FILE}' not found.")
        print("    Run client.py first to generate the key, then restart server.py")
        exit(1)
    with open(KEY_FILE, "rb") as f:
        return f.read()


# ─────────────────────────────────────────────
#  DECRYPT AND VERIFY
#  The payload arriving from the client is
#  structured like this:
#
#  [ IV — 16 bytes ]
#  [ HMAC — 32 bytes ]
#  [ Encrypted file data ]
#
#  We split it apart, check the HMAC first,
#  then decrypt the file data.
# ─────────────────────────────────────────────

def decrypt_and_verify(payload, key):
    # Split the payload into its 3 parts
    iv           = payload[:16]     # first 16 bytes = IV
    received_mac = payload[16:48]   # next 32 bytes  = HMAC
    encrypted    = payload[48:]     # rest           = encrypted data

    # Recalculate the HMAC ourselves using the same key
    expected_mac = hmac.new(key, encrypted, hashlib.sha256).digest()

    # Compare — if they don't match, file was tampered with
    if not hmac.compare_digest(received_mac, expected_mac):
        raise ValueError("INTEGRITY CHECK FAILED — file may have been tampered with!")

    print("    [OK] Integrity check passed — HMAC verified")

    # Decrypt using AES-256-CBC
    cipher    = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)

    return decrypted


# ─────────────────────────────────────────────
#  RECEIVE A FILE FROM THE CLIENT
# ─────────────────────────────────────────────

def receive_file(conn, key):
    # Step 1: receive filename and size (sent as JSON)
    meta_len   = int.from_bytes(conn.recv(4), byteorder="big")
    meta_json  = conn.recv(meta_len).decode()
    metadata   = json.loads(meta_json)
    filename   = metadata["filename"]
    total_size = metadata["size"]

    print(f"\n[+] Incoming file : '{filename}'")
    print(f"    Encrypted size  : {total_size} bytes")

    # Step 2: receive the encrypted file in chunks
    # (large files won't arrive all at once)
    received = b""
    while len(received) < total_size:
        chunk = conn.recv(4096)     # receive 4KB at a time
        if not chunk:
            break
        received += chunk

    print(f"    Received        : {len(received)} bytes")

    # Step 3: verify and decrypt
    try:
        original_data = decrypt_and_verify(received, key)
    except ValueError as e:
        print(f"\n[!] ERROR: {e}")
        conn.send(b"FAILED")
        return

    # Step 4: save the decrypted file
    os.makedirs(SAVE_FOLDER, exist_ok=True)
    save_path = os.path.join(SAVE_FOLDER, filename)
    with open(save_path, "wb") as f:
        f.write(original_data)
    print(f"    [SAVED] Decrypted file : {save_path}")

    # Step 5: also save the encrypted version (for portfolio demo)
    enc_path = os.path.join(SAVE_FOLDER, filename + ".enc")
    with open(enc_path, "wb") as f:
        f.write(received)
    print(f"    [SAVED] Encrypted copy : {enc_path}")

    # Tell the client it was successful
    conn.send(b"SUCCESS")


# ─────────────────────────────────────────────
#  START THE SERVER
# ─────────────────────────────────────────────

def start_server():
    key = load_key()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    print("=" * 50)
    print("  Encrypted File Transfer — SERVER")
    print("  SYNTECXHUB Internship — Project 2")
    print("=" * 50)
    print(f"\n[*] Listening on {HOST}:{PORT}")
    print("[*] Waiting for client...\n")

    while True:
        try:
            conn, addr = server.accept()
            print(f"[+] Client connected from {addr}")
            receive_file(conn, key)
            conn.close()
            print("\n[*] Connection closed. Waiting for next client...\n")
        except KeyboardInterrupt:
            print("\n[*] Server stopped.")
            break

    server.close()


if __name__ == "__main__":
    start_server()