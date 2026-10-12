"""Local encrypted cluster store: AES-256-GCM files with a versioned
header; the cluster name is the AEAD associated data, so renaming or swapping
files on disk makes decryption fail."""
from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..models.cluster import ClusterMetadata
from ..secrets.provider import SecretProvider
from ..settings import Settings, StartupError
from .base import ClusterNotFound, ClusterStore, ClusterStoreError

MAGIC = b"KRBC"
FORMAT_VERSION = 1
HEADER = struct.Struct(">4sB16s12s")  # magic, version, key_id, nonce
SUFFIX = ".kcfg.enc"


class LocalEncryptedStore(ClusterStore):
    def __init__(self, settings: Settings, secret_provider: SecretProvider):
        self.settings = settings
        self._dir = Path(settings.data_dir).expanduser() / "clusters"
        self._key, self._key_id = self._load_key(settings, secret_provider)
        self._prepare_dir()

    # -- setup --------------------------------------------------------------
    @staticmethod
    def _load_key(settings: Settings, secrets_p: SecretProvider) -> tuple[bytes, bytes]:
        ref = settings.store_key_ref
        if not ref:
            raise StartupError("RBAC_UI_STORE_KEY_REF is required for the local store")
        if ref.startswith("vault-transit:"):
            raise StartupError("vault-transit store keys are not implemented yet (P2)")
        raw = secrets_p.get(ref, use_cache=False).get_secret_value()
        try:
            key = base64.b64decode(raw.strip(), validate=True)
        except Exception as exc:  # noqa: BLE001
            raise StartupError("the store key must be 32 bytes of base64") from exc
        if len(key) != 32:
            raise StartupError("the store key must decode to exactly 32 bytes")
        import hashlib
        key_id = hashlib.sha256(key).digest()[:16]
        return key, key_id

    def _prepare_dir(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        data_dir = self._dir.parent
        os.chmod(data_dir, 0o700)
        os.chmod(self._dir, 0o700)
        for p in (data_dir, self._dir):
            mode = stat.S_IMODE(p.stat().st_mode)
            if mode & 0o077:
                raise StartupError(f"{p} is mode {oct(mode)}; it must be 0700")
        for f in self._dir.glob(f"*{SUFFIX}"):
            mode = stat.S_IMODE(f.stat().st_mode)
            if mode & 0o077:
                raise StartupError(f"{f} is mode {oct(mode)}; stored files must be 0600")

    # -- index (plaintext: names only,) ---------------------------------------
    @property
    def _index_path(self) -> Path:
        return self._dir / "index.json"

    def _read_index(self) -> list[str]:
        if not self._index_path.exists():
            return []
        return json.loads(self._index_path.read_text())

    def _write_index(self, names: list[str]) -> None:
        self._atomic_write(self._index_path, json.dumps(sorted(names)).encode())

    # -- crypto --------------------------------------------------------------
    def _encrypt(self, name: str, payload: dict) -> bytes:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(self._key)
        plaintext = json.dumps(payload).encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, name.encode())
        return HEADER.pack(MAGIC, FORMAT_VERSION, self._key_id, nonce) + ciphertext

    def _decrypt(self, name: str, blob: bytes) -> dict:
        if len(blob) < HEADER.size:
            raise ClusterStoreError(f"stored file for {name!r} is corrupt")
        magic, version, key_id, nonce = HEADER.unpack(blob[: HEADER.size])
        if magic != MAGIC or version != FORMAT_VERSION:
            raise ClusterStoreError(f"stored file for {name!r} has an unknown format")
        if key_id != self._key_id:
            raise ClusterStoreError(
                f"stored file for {name!r} was encrypted with a different key "
                "(key_id mismatch); run 'rbac-ui store rotate-key' with the old key available"
            )
        aesgcm = AESGCM(self._key)
        try:
            plaintext = aesgcm.decrypt(nonce, blob[HEADER.size:], name.encode())
        except InvalidTag as exc:
            raise ClusterStoreError(
                f"decryption failed for {name!r}: wrong key, corrupt file, or a "
                "renamed/swapped file (the cluster name is authenticated data)"
            ) from exc
        return json.loads(plaintext)

    # -- file plumbing --------------------------------------------------------
    def _path(self, name: str) -> Path:
        # name is validated as a DNS-1123 label upstream, so it is path-safe.
        return self._dir / f"{name}{SUFFIX}"

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            tmp.rename(path)
            os.chmod(path, 0o600)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)

    # -- ClusterStore ---------------------------------------------------------
    def list_names(self) -> list[str]:
        return self._read_index()

    def _load(self, name: str) -> dict:
        path = self._path(name)
        if not path.exists():
            raise ClusterNotFound(name)
        return self._decrypt(name, path.read_bytes())

    def get_metadata(self, name: str) -> ClusterMetadata:
        return ClusterMetadata.model_validate(self._load(name)["metadata"])

    def get_kubeconfig(self, name: str) -> str:
        return self._load(name)["kubeconfig"]

    def put(self, name: str, kubeconfig_yaml: str, metadata: ClusterMetadata) -> None:
        blob = self._encrypt(name, {
            "kubeconfig": kubeconfig_yaml,
            "metadata": json.loads(metadata.model_dump_json()),
        })
        self._atomic_write(self._path(name), blob)
        names = set(self._read_index())
        names.add(name)
        self._write_index(sorted(names))

    def delete(self, name: str) -> None:
        path = self._path(name)
        if not path.exists():
            raise ClusterNotFound(name)
        # Best-effort overwrite before unlink.
        size = path.stat().st_size
        try:
            with open(path, "r+b") as fh:
                fh.write(secrets.token_bytes(size))
                fh.flush()
                os.fsync(fh.fileno())
        except OSError:
            pass
        path.unlink()
        names = set(self._read_index())
        names.discard(name)
        self._write_index(sorted(names))

    # -- CLI helpers ----------------------------------------------------------
    def verify_all(self) -> dict[str, str]:
        """rbac-ui store verify: check every stored file decrypts."""
        results: dict[str, str] = {}
        for name in self.list_names():
            try:
                self._load(name)
                results[name] = "ok"
            except (ClusterStoreError, ClusterNotFound) as exc:
                results[name] = str(exc)
        return results

    def rotate_key(self, new_key_b64: str) -> int:
        """rbac-ui store rotate-key: re-encrypt every file under a new key_id."""
        new_key = base64.b64decode(new_key_b64.strip(), validate=True)
        if len(new_key) != 32:
            raise ClusterStoreError("the new key must decode to exactly 32 bytes")
        entries = {name: self._load(name) for name in self.list_names()}
        import hashlib
        self._key, self._key_id = new_key, hashlib.sha256(new_key).digest()[:16]
        for name, payload in entries.items():
            self._atomic_write(self._path(name), self._encrypt(name, payload))
        return len(entries)
