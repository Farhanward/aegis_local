from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


PRIVATE_KEY = Path("keys") / "aegis_ed25519_private.pem"
PUBLIC_KEY = Path("keys") / "aegis_ed25519_public.pem"


def ensure_keypair(private_path: str | Path = PRIVATE_KEY, public_path: str | Path = PUBLIC_KEY) -> tuple[Path, Path]:
    private = Path(private_path)
    public = Path(public_path)
    private.parent.mkdir(parents=True, exist_ok=True)
    public.parent.mkdir(parents=True, exist_ok=True)
    if private.exists() and public.exists():
        return private, public
    key = Ed25519PrivateKey.generate()
    private.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return private, public


def load_private_key(path: str | Path = PRIVATE_KEY) -> Ed25519PrivateKey:
    ensure_keypair(path, PUBLIC_KEY)
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_public_key(path: str | Path = PUBLIC_KEY) -> Ed25519PublicKey:
    ensure_keypair(PRIVATE_KEY, path)
    return serialization.load_pem_public_key(Path(path).read_bytes())


def sign_bytes(payload: bytes, private_path: str | Path = PRIVATE_KEY) -> str:
    signature = load_private_key(private_path).sign(payload)
    return base64.urlsafe_b64encode(signature).decode("ascii")


def verify_bytes(payload: bytes, signature: str, public_path: str | Path = PUBLIC_KEY) -> bool:
    try:
        raw = base64.urlsafe_b64decode(signature.encode("ascii"))
        load_public_key(public_path).verify(raw, payload)
        return True
    except Exception:
        return False
