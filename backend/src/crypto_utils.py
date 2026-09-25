import os
from pathlib import Path
from cryptography.fernet import Fernet

# Determine the path for the secret key
PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEY_FILE = PROJECT_ROOT / ".audit_encryption.key"

def _get_or_create_key() -> bytes:
    """Gets the existing encryption key or creates a new one."""
    if os.environ.get("AUDIT_ENCRYPTION_KEY"):
        return os.environ.get("AUDIT_ENCRYPTION_KEY").encode("utf-8")
        
    if KEY_FILE.exists():
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        # Generate a new key and save it securely
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key

# Initialize Fernet cipher suite
_fernet = Fernet(_get_or_create_key())

def encrypt_text(text: str) -> str:
    """Encrypts plaintext string to a URL-safe base64-encoded encrypted string."""
    if not text:
        return text
    return _fernet.encrypt(text.encode("utf-8")).decode("utf-8")

def decrypt_text(encrypted_text: str) -> str:
    """Decrypts encrypted string back to plaintext."""
    if not encrypted_text:
        return encrypted_text
    
    # If the text is somehow unencrypted or invalid, return as-is
    try:
        return _fernet.decrypt(encrypted_text.encode("utf-8")).decode("utf-8")
    except Exception:
        return encrypted_text
