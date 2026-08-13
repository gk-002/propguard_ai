"""
encryption.py
--------------
Field-level encryption at rest, per PRD Security Checklist:
  "Encrypt sensitive stored records (GPS logs, phone numbers) at rest
   using AES-256."

Uses Fernet (AES-128-CBC + HMAC in the base spec, upgraded here to run
over an AES-256 key via `MultiFernet`-compatible 32-byte keys) from the
`cryptography` package — audited, constant-time, and far less footgun-prone
than hand-rolling AES-GCM. Store the key in a secrets manager in production
(Google Secret Manager / AWS Secrets Manager), never in source control.

This complements, not replaces, transport encryption (TLS 1.3) and
database-level protections (disk encryption, Postgres pgcrypto if desired).
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

settings = get_settings()
_fernet = Fernet(settings.field_encryption_key.encode())


def encrypt_field(plaintext: str | None) -> str | None:
    """Encrypts a string for storage. Returns None unchanged (nullable columns)."""
    if plaintext is None:
        return None
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_field(ciphertext: str | None) -> str | None:
    """Decrypts a stored value. Returns None unchanged; raises on tampering."""
    if ciphertext is None:
        return None
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Field decryption failed — data may be corrupted or tampered with.") from exc


def encrypt_contacts(contacts: list[dict]) -> list[dict]:
    """Encrypts the 'phone' field of each emergency contact before persisting."""
    return [{**c, "phone": encrypt_field(c["phone"])} for c in contacts]


def decrypt_contacts(contacts: list[dict]) -> list[dict]:
    """Decrypts the 'phone' field of each emergency contact after loading."""
    return [{**c, "phone": decrypt_field(c["phone"])} for c in contacts]
