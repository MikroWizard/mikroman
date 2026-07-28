#!/usr/bin/python
# -*- coding: utf-8 -*-

# envelope_crypto.py: Envelope encryption helpers for PAM credential storage.
#
# Envelope encryption model:
#   - Each credential gets its own Data Encryption Key (DEK), generated fresh.
#   - The DEK encrypts the actual secret (password, private key passphrase).
#   - The DEK itself is encrypted with the Key Encryption Key (KEK) from kek_provider.
#   - Only encrypted_password and dek_encrypted are stored in the database.
#   - To decrypt: get KEK → decrypt DEK → decrypt payload.
#
# This scheme means:
#   - Rotating the KEK only requires re-encrypting the DEK rows, not the payloads.
#   - A compromised single credential does not expose others (each has its own DEK).
#   - The KEK never touches the database; payloads never touch server-conf.json.
#
# SECURITY NOTE: Never log, print, or return decrypted secrets from any function
# in this module. Callers are responsible for the same constraint.
#
# MikroWizard.com , Mikrotik router management solution
# Author: sepehr.ha@gmail.com

import logging

from cryptography.fernet import Fernet

log = logging.getLogger("envelope_crypto")


def generate_dek() -> bytes:
    """Generate a fresh Data Encryption Key (DEK).

    Returns raw Fernet key bytes. Store only the KEK-encrypted form; never store
    the raw DEK.
    """
    return Fernet.generate_key()


def encrypt_with_kek(dek: bytes, kek: bytes) -> str:
    """Encrypt a DEK with the KEK.

    Args:
        dek: Raw DEK bytes (as returned by generate_dek()).
        kek: KEK bytes (as returned by kek_provider.get_kek()).

    Returns:
        URL-safe base64 string suitable for storing in dek_encrypted column.
    """
    f = Fernet(kek)
    return f.encrypt(dek).decode()


def decrypt_with_kek(encrypted_dek: str, kek: bytes) -> bytes:
    """Decrypt a DEK using the KEK.

    Args:
        encrypted_dek: The stored dek_encrypted string.
        kek: KEK bytes (as returned by kek_provider.get_kek()).

    Returns:
        Raw DEK bytes, ready to pass to encrypt_payload / decrypt_payload.
    """
    f = Fernet(kek)
    return f.decrypt(encrypted_dek.encode())


def encrypt_payload(plaintext: str, dek: bytes) -> str:
    """Encrypt a secret payload (password, passphrase) with a DEK.

    Args:
        plaintext: The secret to encrypt.
        dek: Raw DEK bytes.

    Returns:
        Encrypted string suitable for storing in encrypted_password /
        encrypted_private_key / passphrase_encrypted columns.
    """
    f = Fernet(dek)
    return f.encrypt(plaintext.encode()).decode()


def decrypt_payload(ciphertext: str, dek: bytes) -> str:
    """Decrypt a secret payload using a DEK.

    Args:
        ciphertext: The stored encrypted value.
        dek: Raw DEK bytes (obtained by decrypting dek_encrypted with the KEK).

    Returns:
        Plaintext secret string.

    IMPORTANT: The caller must never log, return in an API response, or persist
    the returned value anywhere other than passing it directly to the terminal
    gateway or another secure internal consumer.
    """
    f = Fernet(dek)
    return f.decrypt(ciphertext.encode()).decode()


def full_encrypt(plaintext: str, kek: bytes) -> dict:
    """Convenience: generate a fresh DEK, encrypt the payload, return both
    encrypted values ready for DB storage.

    Returns:
        {
          'encrypted_payload': str,   # store in encrypted_password column
          'dek_encrypted':     str,   # store in dek_encrypted column
        }
    """
    dek = generate_dek()
    return {
        "encrypted_payload": encrypt_payload(plaintext, dek),
        "dek_encrypted": encrypt_with_kek(dek, kek),
    }


def full_decrypt(encrypted_payload: str, dek_encrypted: str, kek: bytes) -> str:
    """Convenience: decrypt DEK with KEK, then decrypt payload with DEK.

    IMPORTANT: Never log or return the result in any API response.
    """
    dek = decrypt_with_kek(dek_encrypted, kek)
    return decrypt_payload(encrypted_payload, dek)
