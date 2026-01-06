# File Encryption API

A secure FastAPI project for uploading, encrypting, and downloading files.  
Designed to combine **AES encryption** for file contents and **RSA encryption** for key management, all while keeping user authentication safe with **JWT tokens**.

---

## Features

- **User Registration & Login**  
  - Passwords are hashed and salted before storage.
  - Each user has their own RSA key pair for encrypting file keys.

- **File Upload**  
  - Files are encrypted with a **random AES key**.
  - AES keys are encrypted with the user's **RSA public key**.
  - Metadata and encrypted content are stored securely in the database.

- **File Decryption & Download**  
  - Users can download files only if they own them.
  - AES keys are decrypted using the user's private key (unlocked by password).
  - Files are streamed securely with `StreamingResponse` — no raw bytes in JSON.

- **JWT Authentication**  
  - All endpoints require a Bearer token for access.
  - Tokens contain user information for authorization checks.

---

## Tech Stack

- **Backend Framework:** FastAPI  
- **Database:** SQLite   
- **Encryption:**  
  - **AES-256 EAX mode** for file encryption  
  - **RSA (2048-bit)** for key encryption  
- **Authentication:** JWT (PyJWT)  
- **Python Packages:**  
  - `fastapi`, `uvicorn`, `sqlalchemy`, `pycryptodome`, `pydantic` `pwdlib`

---

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/KunMonanz/FileEncryption/
cd FileEncryption
```

### 2. Create virtual environment & install dependencies

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 3. Set environment variables

```python
SECRET_KEY=your_jwt_secret_key_here #in auth.py
```

### 4. Run the API

```bash
uvicorn main:app --reload
```
