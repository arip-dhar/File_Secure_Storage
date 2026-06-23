# 🔒 Advanced Cryptographic Hybrid Vault Storage Engine

An enterprise-grade secure file storage application built with **FastAPI** and **Python**. This system implements a zero-knowledge architecture utilizing a **Hybrid Cryptosystem** (Symmetric AES-Fernet + Asymmetric 2048-bit RSA) to protect data at rest and safely handle multi-user cryptographic sharing permissions.

## 🛡️ Core Security Infrastructure
* **Hybrid Key Encapsulation:** Every uploaded file is encrypted with a unique, randomized symmetric key. The file key itself is then safely wrapped using the owner's 2048-bit RSA Public Key.
* **Zero-Knowledge Deduplication:** Protects against frequency analysis attacks by combining file byte data with a user-specific salt string before calculating the SHA-256 validation fingerprint.
* **Active Disk Integrity Monitoring:** Generates and validates an HMAC-SHA256 signature code over encrypted ciphertexts on disk to neutralize data manipulation vectors.
* **Time-Bound Access Control:** Shared encryption keys are assigned customizable expiration timestamps, automatically self-destructing references upon expiration.
* **Shielded SIEM Audit Logs:** Tracks operational infrastructure events (logins, uploads, transfers, purges) inside a cryptographically masked database tracking trail using an independent logging cipher.

---

## 🚀 How to Run the Project

### 1. Install Required Dependencies
Make sure you have Python installed, then run the pip installer package manager payload using the project manifest:
```bash
pip install -r requirements.txt
python -m venv venv
uvicorn main:app --reload
