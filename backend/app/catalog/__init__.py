"""Offline catalog access."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).parent / "data"


def supported_minors() -> list[str]:
    index = DATA_DIR / "index.json"
    if not index.exists():
        return []
    return json.loads(index.read_text())["minors"]


@lru_cache(maxsize=16)
def load_catalog(minor: str) -> dict:
    path = DATA_DIR / f"catalog-{minor}.json"
    if not path.exists():
        raise FileNotFoundError(f"no offline catalog for Kubernetes {minor}")
    return json.loads(path.read_text())


def best_catalog_for(server_minor: str) -> dict:
    """Pick the matching catalog, else the closest lower, else newest."""
    minors = supported_minors()
    if not minors:
        raise FileNotFoundError("offline catalog not generated; run app.catalog.generate")
    if server_minor in minors:
        return load_catalog(server_minor)
    def key(m: str) -> tuple[int, int]:
        major, _, minor = m.partition(".")
        return int(major), int(minor)
    candidates = [m for m in minors if key(m) <= key(server_minor)] or minors
    return load_catalog(max(candidates, key=key))
