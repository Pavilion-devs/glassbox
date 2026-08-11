"""Small, versioned cryptographic boundary for deployment credentials."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12
_MASTER_KEY_BYTES = 32
_INGESTION_PREFIX = "gbx_ingest_"


@dataclass(frozen=True)
class EncryptedSecret:
    """One AES-GCM ciphertext plus its non-secret key selector."""

    nonce: bytes
    ciphertext: bytes
    key_id: str


class SecretBox:
    """Encrypt control secrets and derive one-way ingestion-key digests."""

    def __init__(self, key: bytes, *, key_id: str = "control-v1") -> None:
        if len(key) != _MASTER_KEY_BYTES:
            raise ValueError("control master key must contain exactly 32 bytes")
        if not key_id or len(key_id) > 64:
            raise ValueError("control master key ID must contain 1 to 64 characters")
        self._key = bytes(key)
        self.key_id = key_id
        self._aead = AESGCM(self._key)

    @classmethod
    def from_base64url(cls, encoded: str, *, key_id: str = "control-v1") -> SecretBox:
        """Load an unpadded base64url-encoded 32-byte key."""

        if not encoded:
            raise ValueError("control master key is unset")
        try:
            padded = encoded + "=" * (-len(encoded) % 4)
            key = base64.urlsafe_b64decode(padded.encode("ascii"))
        except (UnicodeEncodeError, ValueError) as exc:
            raise ValueError("control master key is not valid base64url") from exc
        return cls(key, key_id=key_id)

    @staticmethod
    def generate_base64url() -> str:
        """Generate a new deployment key for delivery to a secret manager."""

        return base64.urlsafe_b64encode(os.urandom(_MASTER_KEY_BYTES)).rstrip(b"=").decode()

    def encrypt(self, value: str, *, aad: bytes) -> EncryptedSecret:
        if not value:
            raise ValueError("secret value must be non-empty")
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._aead.encrypt(nonce, value.encode("utf-8"), aad)
        return EncryptedSecret(nonce=nonce, ciphertext=ciphertext, key_id=self.key_id)

    def decrypt(self, encrypted: EncryptedSecret, *, aad: bytes) -> str:
        if encrypted.key_id != self.key_id:
            raise ValueError("encrypted secret references an unavailable key ID")
        return self._aead.decrypt(encrypted.nonce, encrypted.ciphertext, aad).decode("utf-8")

    def issue_ingestion_key(self) -> tuple[str, str, str]:
        """Return the clear key once, its display prefix, and its stored digest."""

        clear = _INGESTION_PREFIX + base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        return clear, clear[:20], self.ingestion_key_digest(clear)

    def ingestion_key_digest(self, clear: str) -> str:
        if not clear.startswith(_INGESTION_PREFIX) or len(clear) < 40:
            return ""
        return hmac.new(
            self._key,
            b"glassbox.ingestion-key.v1\0" + clear.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def ingestion_key_matches(self, clear: str, expected_digest: str) -> bool:
        actual = self.ingestion_key_digest(clear)
        return bool(actual) and hmac.compare_digest(actual, expected_digest)


def datahub_secret_aad(*, organization: str, connection_id: str) -> bytes:
    """Bind ciphertext to its exact deployment record and format."""

    return f"glassbox.datahub-token.v1\0{organization}\0{connection_id}".encode()
