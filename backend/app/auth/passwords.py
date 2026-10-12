"""Password hashing and policy. Argon2id m=64MiB t=3 p=4."""
from __future__ import annotations

from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Fallback when settings are unavailable; normally RBAC_UI_MIN_PASSWORD_LENGTH
# (default 6) decides.
MIN_PASSWORD_LENGTH = 6


def _min_length() -> int:
    try:
        from ..settings import get_settings
        return get_settings().min_password_length
    except Exception:  # noqa: BLE001 — e.g. CLI before settings init
        return MIN_PASSWORD_LENGTH

_hasher = PasswordHasher(
    time_cost=3, memory_cost=64 * 1024, parallelism=4, hash_len=32, type=Type.ID
)

# A dummy hash verified for unknown usernames so timing does not reveal
# which usernames exist.
DUMMY_HASH = _hasher.hash("dummy-password-for-timing-equalization")

_COMMON_PASSWORDS_FILE = Path(__file__).parent / "common_passwords.txt"
_common_passwords: frozenset[str] | None = None


def _common() -> frozenset[str]:
    global _common_passwords
    if _common_passwords is None:
        _common_passwords = frozenset(
            line.strip().lower()
            for line in _COMMON_PASSWORDS_FILE.read_text().splitlines()
            if line.strip()
        )
    return _common_passwords


class PasswordPolicyError(ValueError):
    pass


def check_policy(password: str) -> None:
    """Configurable minimum length (RBAC_UI_MIN_PASSWORD_LENGTH,
    default 6), not in the bundled common-password list."""
    min_len = _min_length()
    if len(password) < min_len:
        raise PasswordPolicyError(
            f"password must be at least {min_len} characters"
        )
    if password.lower() in _common():
        raise PasswordPolicyError("password is on the common-password list")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time-ish verification; False on mismatch or malformed hash."""
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def verify_dummy(password: str) -> None:
    """Burn the same Argon2 work for unknown usernames."""
    try:
        _hasher.verify(DUMMY_HASH, password)
    except VerifyMismatchError:
        pass


def looks_like_argon2_hash(value: str) -> bool:
    return value.startswith("$argon2")
