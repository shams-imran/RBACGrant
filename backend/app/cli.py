"""rbac-ui CLI: hash-password, store verify / rotate-key / migrate.
Secrets are never accepted as CLI flags — they are prompted or come
from the environment/secret refs."""
from __future__ import annotations

import argparse
import getpass
import sys

from .auth import passwords
from .secrets.provider import SecretProvider
from .settings import Settings, StartupError


def cmd_hash_password(_args: argparse.Namespace) -> int:
    """Prompt twice without echo, enforce the policy, print a hash."""
    pw1 = getpass.getpass("New admin password: ")
    pw2 = getpass.getpass("Repeat password: ")
    if pw1 != pw2:
        print("passwords do not match", file=sys.stderr)
        return 1
    try:
        passwords.check_policy(pw1)
    except passwords.PasswordPolicyError as exc:
        print(f"rejected: {exc}", file=sys.stderr)
        return 1
    print(passwords.hash_password(pw1))
    print("\nStore this hash in RBAC_UI_ADMIN_PASSWORD_HASH or in Vault "
          "(RBAC_UI_ADMIN_PASSWORD_REF).", file=sys.stderr)
    return 0


def _local_store(settings: Settings):
    from .store.local_encrypted import LocalEncryptedStore
    return LocalEncryptedStore(settings, SecretProvider(settings))


def cmd_store_verify(_args: argparse.Namespace) -> int:
    settings = Settings()
    if settings.cluster_store != "local":
        print("store verify applies to RBAC_UI_CLUSTER_STORE=local", file=sys.stderr)
        return 1
    try:
        store = _local_store(settings)
    except StartupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    results = store.verify_all()
    if not results:
        print("no clusters stored")
        return 0
    bad = 0
    for name, status in sorted(results.items()):
        print(f"{name}: {status}")
        if status != "ok":
            bad += 1
    return 1 if bad else 0


def cmd_store_rotate_key(_args: argparse.Namespace) -> int:
    settings = Settings()
    if settings.cluster_store != "local":
        print("rotate-key applies to RBAC_UI_CLUSTER_STORE=local", file=sys.stderr)
        return 1
    new_key = getpass.getpass("New 32-byte base64 key: ")
    try:
        store = _local_store(settings)
        n = store.rotate_key(new_key)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"re-encrypted {n} cluster(s) under the new key. Update "
          "RBAC_UI_STORE_KEY_REF to point at the new key now.")
    return 0


def cmd_store_migrate(args: argparse.Namespace) -> int:
    """Move entries between backends."""
    settings = Settings()
    from .store.local_encrypted import LocalEncryptedStore
    from .store.vault_store import VaultClusterStore
    provider = SecretProvider(settings)

    def make(kind: str):
        if kind == "local":
            return LocalEncryptedStore(settings, provider)
        if kind == "vault":
            return VaultClusterStore(settings, provider)
        raise SystemExit(f"unknown backend {kind!r}")

    src, dst = make(args.from_backend), make(args.to_backend)
    names = src.list_names()
    for name in names:
        dst.put(name, src.get_kubeconfig(name), src.get_metadata(name))
        print(f"migrated {name}")
    print(f"done: {len(names)} cluster(s). The source entries were kept; "
          "delete them once you have verified the target backend.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rbac-ui")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("hash-password", help="hash an admin password")

    store = sub.add_parser("store", help="local encrypted store maintenance")
    store_sub = store.add_subparsers(dest="store_command", required=True)
    store_sub.add_parser("verify", help="check every stored file decrypts")
    store_sub.add_parser("rotate-key", help="re-encrypt under a new key")
    migrate = store_sub.add_parser("migrate", help="move entries between backends")
    migrate.add_argument("--from", dest="from_backend", required=True, choices=["local", "vault"])
    migrate.add_argument("--to", dest="to_backend", required=True, choices=["local", "vault"])

    args = parser.parse_args(argv)
    if args.command == "hash-password":
        return cmd_hash_password(args)
    if args.command == "store":
        if args.store_command == "verify":
            return cmd_store_verify(args)
        if args.store_command == "rotate-key":
            return cmd_store_rotate_key(args)
        if args.store_command == "migrate":
            return cmd_store_migrate(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
