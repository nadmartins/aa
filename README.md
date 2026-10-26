# 3S — Secure Streaming Service (Part I)
**Computer Systems Security (SSC) — 2026/2027**

## Authors
- Nelson Martins — Nº 73954
- Ricardo Ferreira — Nº 77152

---

## 1. Project Overview
3S (Secure Streaming Service) is a secure, real-time media streaming system consisting of an origin **Secure Stream Server** and an intermediate **Secure Proxy** serving standard web browsers.

### Security Guarantees:
- **Confidentiality:** End-to-end symmetric encryption for all media blocks and protocol payloads (AES, ChaCha20, RC6).
- **Integrity & Authenticity:** Authenticated encryption (AEAD: GCM, CCM, Poly1305) or Encrypt-then-MAC (HMAC-SHA256, HMAC-SHA384, HMAC-SHA512).
- **Replay Protection:** Unique session nonces (`SECX`), challenge nonces (`SRV`), and strictly monotonic block sequence numbers (`SEQB`).
- **Message Ordering & Stream Completeness:** Strict sequence validation preventing reordering, injection, dropping, or truncation attacks.
- **Dynamic Configuration:** Cryptographic suites, key lengths, IVs, padding schemes, and MAC algorithms are fully externalized in XML configuration files.

---

## 2. Compilation Instructions

From the repository root (`proj1`):

### Windows (PowerShell / Command Prompt):
```powershell
javac -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar;WA1-Materials" WA1-Materials/common/*.java WA1-Materials/streamserver/*.java WA1-Materials/streamproxy/*.java
```

### Linux / macOS:
```bash
javac -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar:WA1-Materials" WA1-Materials/common/*.java WA1-Materials/streamserver/*.java WA1-Materials/streamproxy/*.java
```

---

## 3. Running the System

Open two separate terminals from the project root directory.

### Terminal 1 — Start the Secure Stream Server:
```powershell
# Usage: java -cp <cp> streamserver.StreamServer [port] [mediaDir] [configFile]
java -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar;WA1-Materials" streamserver.StreamServer 8081 "WA1-Materials/streamserver/media" "WA1-Materials/streamserver/sservercrypto.config"
```

### Terminal 2 — Start the Secure Stream Proxy:
```powershell
# Usage: java -cp <cp> streamproxy.ProxySocketServer [port] [originHost] [originPort] [configFile]
java -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar;WA1-Materials" streamproxy.ProxySocketServer 8080 localhost 8081 "WA1-Materials/streamproxy/proxycrypto.config"
```

### Access via Web Browser:
Open your browser and navigate to:
```
http://localhost:8080/
```
Click **Play Stream** to watch `sample.mp4` streamed and decrypted in real time.

---

## 4. Automated Security & Multi-Config Testbenches

To run the automated validation testbenches:

### 4.1 Security Threat & Mitigations Testbench
Verifies end-to-end data integrity, replay attack detection, tampering mitigation, out-of-order block detection, and handshake policy enforcement:
```powershell
javac -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar;WA1-Materials" WA1-Materials/scratch/IntegrationSecurityTestbench.java
java -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar;WA1-Materials;WA1-Materials/scratch" IntegrationSecurityTestbench
```

### 4.2 Multi-Configuration Interoperability Testbench
Tests 10 distinct cipher suites (AES-GCM, AES-CCM, ChaCha20-Poly1305, RC6-GCM, AES-CTR+HMAC, AES-CBC+HMAC, AES-ECB+HMAC, RC6-CTR+HMAC, RC6-CBC+HMAC, ChaCha20+HMAC) ensuring 100% SHA-256 hash match:
```powershell
javac -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar;WA1-Materials" WA1-Materials/scratch/MultiConfigTestbench.java
java -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar;WA1-Materials;WA1-Materials/scratch" MultiConfigTestbench
```

### 4.3 Parallel / Concurrent Clients Testbench
Simulates 8 concurrent proxies streaming in parallel:
```powershell
javac -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar;WA1-Materials" WA1-Materials/scratch/ConcurrencyTestbench.java
java -cp "WA1-Materials/lib/bcprov-jdk18on-1.86.jar;WA1-Materials;WA1-Materials/scratch" ConcurrencyTestbench
```

---

## 5. Supported Cryptographic Configurations

Configuration files are located in `WA1-Materials/configs/` and can be passed as arguments:

| Configuration File | Algorithm | Mode | Padding | MAC Algorithm | Security Properties |
|---|---|---|---|---|---|
| `aes-gcm.xml` | AES (256/128-bit) | GCM | None | AEAD | AEAD Authenticated Encryption |
| `aes-ccm.xml` | AES (256-bit) | CCM | None | AEAD | AEAD Authenticated Encryption |
| `chacha20-poly1305.xml` | ChaCha20 (256-bit) | Poly1305 | None | AEAD | Stream Cipher + Poly1305 AEAD |
| `rc6-gcm.xml` | RC6 (256/128-bit) | GCM | None | AEAD | BouncyCastle RC6 block AEAD |
| `aes-ctr-hmac.xml` | AES (256-bit) | CTR | NoPadding | HMAC-SHA256 | Encrypt-then-MAC Stream Mode |
| `aes-cbc-hmac.xml` | AES (256-bit) | CBC | PKCS5Padding | HMAC-SHA256 | Encrypt-then-MAC Block Mode |
| `aes-ecb-hmac.xml` | AES (256-bit) | ECB | PKCS5Padding | HMAC-SHA256 | Encrypt-then-MAC Block Mode |
| `rc6-ctr-hmac.xml` | RC6 (256-bit) | CTR | NoPadding | HMAC-SHA256 | Encrypt-then-MAC Stream Mode |
| `rc6-cbc-hmac.xml` | RC6 (256-bit) | CBC | PKCS5Padding | HMAC-SHA256 | Encrypt-then-MAC Block Mode |
| `chacha20-hmac.xml` | ChaCha20 (256-bit) | NULL | None | HMAC-SHA256 | Pure Stream Cipher + HMAC |
