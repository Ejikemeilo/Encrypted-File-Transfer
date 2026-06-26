# Encrypted File Transfer & Secure File Storage

**SYNTECXHUB Internship — Project 2**  
**Author:** Ejikeme Cyril Ilo  
**GitHub:** [github.com/Ejikemeilo](https://github.com/Ejikemeilo)

---

## Project Overview

A Python-based client-server system that encrypts files using AES-256 before transferring them over a network socket. The server verifies file integrity using HMAC-SHA256 before decrypting and saving the file to disk. Both the decrypted original and the encrypted copy are stored on the server side.

This project was built as part of the **SYNTECXHUB Cybersecurity Internship Program**.

---

## Features

- AES-256-CBC encryption on every file before transfer
- Random IV (Initialization Vector) generated per session — same file encrypted twice produces different output
- HMAC-SHA256 integrity verification — server detects any tampering before decrypting
- Socket-based file transfer between client and server
- Encrypted copy saved to disk alongside the decrypted original
- Automatic key generation on first run — saved to `transfer.key`
- Clean triage output showing every step of the process

---

## How It Works

```
CLIENT SIDE                          SERVER SIDE
-----------                          -----------
Read file from disk
Generate random IV
Encrypt with AES-256-CBC
Generate HMAC-SHA256
Bundle: IV + HMAC + Encrypted data
Send over socket               --->  Receive encrypted payload
                                     Split into IV, HMAC, data
                                     Recalculate HMAC
                                     Compare HMACs (integrity check)
                                     Decrypt with AES-256-CBC
                                     Save decrypted file to disk
                                     Save encrypted copy to disk
Receive SUCCESS confirmation   <---  Send SUCCESS
```

---

## Payload Structure

Every file is sent as a single binary payload structured like this:

```
[ IV — 16 bytes ] [ HMAC — 32 bytes ] [ Encrypted file data ]
```

- **IV** — Initialization Vector, unique per transfer, needed for decryption
- **HMAC** — SHA-256 fingerprint of the encrypted data, used to detect tampering
- **Encrypted data** — AES-256-CBC encrypted file content

---

## Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.x | Core language |
| `pycryptodome` | AES-256 encryption and decryption |
| `hmac` + `hashlib` | HMAC-SHA256 integrity verification |
| `socket` | Client-server file transfer |
| `json` | File metadata exchange |

---

## Project Structure

```
Encrypted File Transfer/
│
├── server.py              # Receiver — verifies, decrypts, saves
├── client.py              # Sender — encrypts and transfers
├── transfer.key           # AES-256 shared secret key (auto-generated)
├── secret.txt             # Example file used for testing
└── received_files/
    ├── secret.txt         # Decrypted file saved by server
    └── secret.txt.enc     # Encrypted copy saved by server
```

---

## How to Run

### Prerequisites

Install the only external dependency:

```bash
pip install pycryptodome
```

### Step 1 — Run the client once to generate the key

```bash
python client.py
```

Enter any filename when prompted. It will fail to connect (server isn't running yet) but the key file `transfer.key` will be created.

### Step 2 — Start the server

```bash
python server.py
```

Leave this terminal open. The server will wait for incoming connections.

### Step 3 — Open a second terminal and run the client

```bash
python client.py
```

Enter the filename you want to transfer. The file will be encrypted, sent, verified, and saved.

---

## Sample Output

**Client terminal:**
```
==================================================
  Encrypted File Transfer — CLIENT
  SYNTECXHUB Internship — Project 2
==================================================
[+] Loaded existing key from 'transfer.key'

Enter the name of the file to send: secret.txt

[*] Encrypting 'secret.txt'...
    [+] Original file size : 154 bytes
    [+] Encrypted size     : 208 bytes
    [+] IV   : 658269c65fa4b65ced838790db0fbb1e...
    [+] HMAC : c6e9d52f4022a4e74dd9faab16c7d913...

[*] Connecting to server at 127.0.0.1:9999...
[+] Connected!
[*] Sending encrypted file...

[SUCCESS] 'secret.txt' was encrypted, transferred, and verified!
          Check the server's 'received_files' folder.
```

**Server terminal:**
```
==================================================
  Encrypted File Transfer — SERVER
  SYNTECXHUB Internship — Project 2
==================================================
[*] Listening on 127.0.0.1:9999
[*] Waiting for client...

[+] Client connected from ('127.0.0.1', 54321)

[+] Incoming file : 'secret.txt'
    Encrypted size  : 208 bytes
    Received        : 208 bytes
    [OK] Integrity check passed — HMAC verified
    [SAVED] Decrypted file : received_files\secret.txt
    [SAVED] Encrypted copy : received_files\secret.txt.enc
```

---

## Threat Model

| Threat | How This Project Defends Against It |
|--------|-------------------------------------|
| Eavesdropping (MITM) | AES-256 encryption — intercepted data is unreadable without the key |
| File tampering | HMAC-SHA256 — any change to the file in transit is detected |
| Replay attacks | Random IV per session — same file produces different ciphertext each time |
| Key theft | Key stored locally in `transfer.key` — never transmitted over the network |

---

## What I Learned

- How AES-256-CBC encryption works in practice
- What an IV is and why it matters for encryption security
- How HMAC works as a message authentication code
- How to build a client-server file transfer system using Python sockets
- How to structure encrypted payloads (IV + HMAC + ciphertext)
- The difference between encryption (confidentiality) and HMAC (integrity)

---

## License

This project is for educational use as part of the SYNTECXHUB Internship Program.

---

## Author

**Ejikeme Cyril Ilo**  
IT Officer & Project Manager | Cybersecurity Trainee  
Abuja, Nigeria  
[github.com/Ejikemeilo](https://github.com/Ejikemeilo)
