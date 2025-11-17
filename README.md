# SecureChat – Information Security Assignment #2 (CS-3002, Fall 2025)

**Developer:** Omer Mustafa (Roll No: 1180)

This project implements a **console-based Secure Chat System** using **Python**, demonstrating end-to-end application-layer cryptography to achieve:

**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)** without relying on TLS/SSL.

> Project Repository:  
> https://github.com/m-umer-mustafa/securechat-skeleton


## 🎯 System Overview

This implementation operates over **plain TCP connections** and handles all cryptographic operations explicitly at the **application layer**:

- **Public Key Infrastructure (PKI)** with Root CA and leaf certificates for client/server
- **X.509 Certificate Validation**: Verifies CA signatures, validity periods, and hostname matching (CN/SAN)
- **Ephemeral Diffie-Hellman (DH)** key exchange for deriving shared AES-128 encryption keys
- **AES-128-ECB** encryption with PKCS#7 padding for registration, login, and session messages
- **AES-128-CBC** encryption with PKCS#7 padding and RSA digital signatures for chat messages
- **MySQL database** for user credentials with salted SHA-256 password hashing
- **Session transcripts** with cryptographic signatures for non-repudiation
- **Certificate generation scripts** for creating CA and issuing client/server certificates


## 📁 Project Structure

```
securechat-skeleton/
├─ app/
│  ├─ client.py              # Client implementation (TCP, PKI, DH, auth, chat)
│  ├─ server.py              # Server implementation (TCP, validation, DH, auth, chat)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128-ECB encryption with PKCS#7
│  │  ├─ dh.py               # Diffie-Hellman key exchange utilities
│  │  ├─ pki.py              # X.509 certificate validation logic
│  │  ├─ chat.py             # Signed and encrypted chat message format (CBC + RSA)
│  │  └─ sign.py             # RSA signature utilities (placeholder)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic models for protocol messages
│  │  └─ utils.py            # Helper functions (base64, hashing, I/O)
│  └─ storage/
│     ├─ db.py               # MySQL operations with salted password hashing
│     └─ transcript.py       # Session transcript utilities (placeholder)
├─ certs/
│  ├─ ca/                    # Root Certificate Authority files
│  ├─ client/                # Client certificate and private key
│  ├─ server/                # Server certificate and private key
│  ├─ fake_ca/               # Test CA for certificate validation failures
│  └─ fake_server/           # Test server cert for validation failures
├─ scripts/
│  ├─ gen_ca.py              # Script to generate Root CA
│  └─ gen_cert.py            # Script to issue certificates signed by CA
├─ tests/
│  └─ manual/
│     ├─ NOTES.md            # Manual testing guidelines
│     └─ repu_veri.py        # Offline session receipt verification utility
├─ server_session_receipt.txt
├─ client_session_receipt.txt
├─ requirements.txt
└─ README.md
```


## 🏗️ Folder Structure

```
securechat/
├─ app/
│  ├─ client.py              # Client workflow (TCP, cert exchange, DH, login, chat, receipts)
│  ├─ server.py              # Server workflow (TCP, cert validation, DH, login, chat, receipts)
│  ├─ crypto/
│  │  ├─ aes.py              # AES-128(ECB)+PKCS#7 helpers
│  │  ├─ dh.py               # DH helpers + AES key derivation
│  │  ├─ pki.py              # X.509 validation (CA signature, validity, CN/SAN)
│  │  ├─ chat.py             # Signed & encrypted chat message format (CBC + RSA)
│  │  └─ sign.py             # RSA sign/verify (not used directly in current code)
│  ├─ common/
│  │  ├─ protocol.py         # Pydantic models (not used in the final flow)
│  │  └─ utils.py            # Helpers for base64, SHA-256, and framed I/O
│  └─ storage/
│     ├─ db.py               # MySQL user store (salted SHA-256 passwords)
│     └─ transcript.py       # (not used – session receipts handled in client/server)
├─ certs/
│  ├─ ca/                    # Root CA key/cert
│  ├─ client/                # Client key/cert
│  ├─ server/                # Server key/cert
│  ├─ fake_ca/               # Fake CA (for BAD_CERT tests)
│  └─ fake_server/           # Fake server cert/key (for BAD_CERT tests)
├─ scripts/
│  ├─ gen_ca.py              # Create Root CA
│  └─ gen_cert.py            # Issue client/server certs signed by Root CA
├─ tests/
│  └─ manual/
│     ├─ NOTES.md            # Manual testing checklist
│     └─ repu_veri.py        # Offline SessionReceipt verification helper
├─ server_session_receipt.txt
├─ client_session_receipt.txt
├─ requirements.txt
└─ README.md
```




## ⚙️ Setup and Configuration

### Step 1: Python Virtual Environment

Set up an isolated Python environment:

```bash
python -m venv .venv

# For Linux/macOS:
source .venv/bin/activate

# For Windows PowerShell:
.venv\Scripts\Activate.ps1

# Install dependencies:
pip install -r requirements.txt
```

### Step 2: MySQL Database Setup

The application requires MySQL with the following default settings (configurable via environment variables):

- **Host**: `127.0.0.1`
- **Port**: `3306`
- **Username**: `scuser`
- **Password**: `scpass`
- **Database**: `securechat`

Environment variables for customization:
- `DB_HOST`
- `DB_PORT`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`

#### Docker-based MySQL Setup (Recommended)

```bash
docker run -d --name securechat-mysql \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=securechat \
  -e MYSQL_USER=scuser \
  -e MYSQL_PASSWORD=scpass \
  -p 3306:3306 mysql:8
```

Initialize database schema:

```bash
python -m app.storage.db --init
```


### Step 3: Certificate Generation

Generate certificates if not already present:

```bash
# Create Root Certificate Authority
python scripts/gen_ca.py --name "FAST-NU Root CA"

# Generate server certificate
python scripts/gen_cert.py --cn server.local --out certs/server

# Generate client certificate
python scripts/gen_cert.py --cn client.local --out certs/client
```

Expected certificate locations:

- Root CA: `certs/ca/ca_cert.pem`
- Server: `certs/server/cert.pem`, `certs/server/key.pem`
- Client: `certs/client/cert.pem`, `certs/client/key.pem`




## 🚀 Running the Application

### Starting the Server

Launch the server in one terminal:

```bash
python -m app.server
```

**Server Execution Flow:**

1. Listens for TCP connections on `0.0.0.0:9000`
2. Receives client certificate and performs validation:
   - Verifies CA signature
   - Checks validity period
   - Validates hostname (`client.local`)
3. Transmits server certificate to client
4. Executes DH key exchange to derive initial **AES-128 encryption key**
5. Receives and decrypts **registration** data, creates user in database
6. Receives and decrypts **authentication** request, verifies credentials
7. Upon successful authentication:
   - Performs second DH exchange for **session-specific AES key**
   - Sends encrypted session confirmation
   - Enters secure **chat mode** with signed messages
   - On session end, generates `server_session_receipt.txt` containing transcript, SHA256 hash, and RSA signature

### Starting the Client

In a separate terminal, launch the client:

```bash
python -m app.client
```

**Client Execution Flow:**

1. Establishes TCP connection to `127.0.0.1:9000`
2. Loads Root CA certificate and client credentials
3. Transmits client certificate to server
4. Receives server certificate and validates it (CA signature, hostname `server.local`)
5. Performs DH key exchange to derive initial **AES encryption key**
6. Sends AES-128-ECB encrypted **registration** payload:
   - JSON format: `{"type": "register", "email": "...", "username": "...", "password": "..."}`
   - Note: Currently hardcoded in `app.client`
7. Sends AES-128-ECB encrypted **authentication** request
8. Receives encrypted authentication response: `{"status": "ok" | "error"}`
9. If authentication succeeds:
   - Performs second DH exchange for **session-specific AES key**
   - Receives encrypted session-ready confirmation
   - Enters interactive **secure chat mode**

10. On exit, generates `client_session_receipt.txt` with transcript, SHA256 hash, and RSA signature

> **Note**: Registration and authentication credentials are currently hardcoded in `app.client`:
> ```python
> user_email = "alice14@example.com"
> user_name = "alice14"
> user_password = "supersecret"
> ```


## 🚀 Execution Steps

### 1. Start the Server

```bash
python -m app.server
```

Server flow (`app.server`):

1. Waits for TCP connections on `0.0.0.0:9000`.
2. Receives client certificate and verifies it:
   - Signed by Root CA.
   - Within validity interval.
   - Hostname matches `client.local`.
3. Sends its own server certificate.
4. Runs DH to derive an **AES-128 key** (`aes_key`).
5. Receives and decrypts **registration** payload, creates DB user.
6. Receives and decrypts **login** payload, verifies password.
7. If login OK:
   - Runs a second DH to derive a **session AES key** (`session_aes_key`).
   - Sends encrypted `"session ready"` message.
   - Enters encrypted **chat loop** with signed messages.
   - On disconnect, writes `server_session_receipt.txt` with transcript, SHA256 hash, and RSA signature.

### 2. Start the Client

In another terminal:

```bash
python -m app.client
```

Client flow (`app.client`):

1. Connects to `127.0.0.1:9000`.
2. Loads Root CA + client cert/key.
3. Sends client certificate.
4. Receives and validates server certificate (signed-by CA, hostname `server.local`).
5. Runs DH to derive **AES key** (`aes_key`).
6. Sends AES-128-ECB encrypted **registration** JSON:
   - `{"type": "register", "email": "...", "username": "...", "password": "..."}` (hardcoded).
7. Sends AES-128-ECB encrypted **login** JSON for the same username/password.
8. Receives AES-128-ECB encrypted login response (`{"status": "ok" | "error"}`).
9. If status is `ok`:
   - Runs second DH to derive **session AES key** (`session_aes_key`).
   - Receives AES-encrypted `"session ready"` message.
   - Enters interactive **chat loop**, sending signed & encrypted messages.

10. On exit, writes `client_session_receipt.txt` with transcript, SHA256 hash, and RSA signature.

> Note: registration/login credentials are currently **hardcoded** in `app.client`:
> ```python
> email = "alice14@example.com"
> username = "alice14"
> password = "supersecret"
> ```


## 💬 Chat Message Format

Implemented in [`app.crypto.chat`](app/crypto/chat.py).

Each chat message is framed as:

- **Outer framing**:  
  `[4-byte big-endian length][JSON bytes]`

- **JSON structure**:
  ```json
  {
    "seqno": <int>,     // monotonically increasing
    "ts": <float>,      // timestamp (seconds)
    "iv": "<hex>",      // 16-byte IV for AES-CBC
    "ct": "<hex>",      // AES-128-CBC ciphertext
    "sig": "<hex>"      // RSA PKCS#1 v1.5 signature over SHA256(seqno || ts || ct)
  }
  ```

Encryption/signing:

- AES mode: **CBC**, key `session_aes_key` (16 bytes).
- Padding: **PKCS#7**.
- Signature: RSA PKCS#1 v1.5 with SHA-256 over:
  `seqno || ts || ct` (packed via `struct.pack`).

Verification:

- `parse_chat_message(...)`:
  - Checks message length framing.
  - Enforces **strictly increasing `seqno`** (replay protection).
  - Recomputes hash and verifies RSA signature using peer’s public key.
  - Decrypts AES-CBC and unpads to get plaintext string.


## 📥 Sample Input / Output

### 1. Registration & Login (over AES-ECB)

From client side (plaintext before encryption):

```json
{
  "type": "register",
  "email": "alice14@example.com",
  "username": "alice14",
  "password": "supersecret"
}
```

```json
{
  "type": "login",
  "username": "alice14",
  "password": "supersecret"
}
```

Server plaintext response (before encryption):

```json
{"status": "ok"}
```

or

```json
{"status": "error", "reason": "invalid_credentials"}
```

On the wire, all of these are AES-128-ECB encrypted and framed as:

- `[4-byte big-endian length][ciphertext bytes]`.

### 2. Chat (interactive)

Example console session:

**Client:**

```text
> ugh i hate this bruh
[CHAT_RX] from server: Echo: ugh i hate this bruh
> sigh
[CHAT_RX] from server: Echo: sigh
> 
Client exited.
```

**Server:**

```text
[CHAT_RX] from ('127.0.0.1', 12345): 'ugh i hate this bruh'
[CHAT_RX] from ('127.0.0.1', 12345): 'sigh'
[CHAT] client ('127.0.0.1', 12345) disconnected
Server exited.
```




## 🧾 Session Receipts and Non-Repudiation

Both client and server generate session receipts at the end of each chat session:

- **Client Receipt**: `client_session_receipt.txt`
- **Server Receipt**: `server_session_receipt.txt`

### Receipt Format

```text
TRANSCRIPT:
TX|1|1763327230.0977857|server|test message one
RX|1|1763327230.0992265|server|Echo: test message one
...

HASH:<SHA256 hexadecimal digest of transcript>
SIG:<RSA signature hexadecimal over HASH>
```

### Offline Verification

Verify receipt authenticity using the provided verification script:

```bash
python tests/manual/repu_veri.py
```

**Note**: Update `RECEIPT_FILE_PATH` and `CERTIFICATE_FILE_PATH` variables in the script as needed.


## 🔬 Security Testing and Validation

Refer to `tests/manual/NOTES.md` for a complete testing checklist.

### Recommended Tests

**1. Encryption Verification (Wireshark)**
- Capture network traffic on port 9000
- Verify that registration, authentication, and chat payloads are encrypted
- Confirm no plaintext credentials or messages are visible on the wire

**2. Certificate Validation (BAD_CERT)**
- Test with `certs/fake_ca` or `certs/fake_server` certificates
- Verify that the system correctly rejects invalid certificates
- Confirm appropriate error logging

**3. Tampering Detection (SIG_FAIL)**
- Commented code exists in `app.client` to flip bits in ciphertext
- Enable tampering code to verify signature verification fails
- Confirm server logs `[SIG_INVALID]` and rejects modified messages

**4. Replay Attack Prevention (REPLAY)**
- Commented code exists in `app.client` to resend messages with old sequence numbers
- Enable replay code to verify `parse_chat_message` rejects non-increasing sequence numbers
- Confirm replay protection works correctly

**5. Non-Repudiation Verification**
- Use `tests/manual/repu_veri.py` to validate session receipts
- Verify RSA signatures on transcript hashes
- Confirm receipts can be verified offline


## 📋 Assignment Requirements Compliance

This implementation satisfies all assignment requirements:

- ✅ **No TLS/SSL**: All cryptography implemented at application layer over plain TCP
- ✅ **Cryptographic Libraries**: Uses standard libraries (`cryptography`, etc.) - no manual crypto implementation required
- ✅ **No Secrets in Repository**: Certificates and keys excluded from version control
- ✅ **Progressive Development**: Codebase refactored to demonstrate independent implementation

---

**Author**: Omer Mustafa  
**Roll Number**: 1180  
**Course**: CS-3002 Information Security, Fall 2025  
**Institution**: FAST-NUCES

````


