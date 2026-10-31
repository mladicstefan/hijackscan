"""Shared plumbing for fetch targets: config, HTTP client, atomic downloads, manifest."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml
from tenacity import (
    RetryCallState,
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential_jitter,
)

log = logging.getLogger("hijackscan.fetch")

DEFAULT_CONFIG = Path("config/fetch.yaml")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


def load_config(path: Path | None = None, overrides: dict[str, Any] | None = None) -> dict[str, Any]:
    """Load config/fetch.yaml and apply dotted-key overrides (e.g. {"caida.date": "2026-07-01"})."""
    path = path or DEFAULT_CONFIG
    with path.open() as f:
        cfg: dict[str, Any] = yaml.safe_load(f)
    for key, value in (overrides or {}).items():
        if value is None:
            continue
        node = cfg
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    cfg["user_agent"] = cfg["user_agent"].format(email=cfg["contact_email"])
    return cfg


def resolve_date(value: Any) -> date:
    """Turn a config date ("today", ISO string, date) into a date."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if str(value).lower() == "today":
        return datetime.now(UTC).date()
    return date.fromisoformat(str(value))


def resolve_datetime(value: Any) -> datetime:
    """Parse ISO datetimes with a trailing Z or offset; naive input is taken as UTC."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


@dataclass
class ManifestEntry:
    target: str
    url: str
    path: str
    bytes: int
    sha256: str
    fetched_at: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True)


class Manifest:
    """data/MANIFEST.jsonl: one line per local file, keyed by local path, rewritten atomically."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self.entries: dict[str, ManifestEntry] = {}
        if path.exists():
            with path.open() as f:
                for line in f:
                    line = line.strip()
                    if line:
                        d = json.loads(line)
                        self.entries[d["path"]] = ManifestEntry(**d)

    def get(self, path: Path) -> ManifestEntry | None:
        return self.entries.get(str(path))

    def record(self, entry: ManifestEntry) -> None:
        with self._lock:
            self.entries[entry.path] = entry
            self._flush()

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".jsonl.part")
        with tmp.open("w") as f:
            for e in sorted(self.entries.values(), key=lambda e: e.path):
                f.write(e.to_json() + "\n")
        os.replace(tmp, self.path)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def write_atomic(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".part")
    mode = "wb" if isinstance(data, bytes) else "w"
    with tmp.open(mode) as f:
        f.write(data)
    os.replace(tmp, path)


def write_json_atomic(path: Path, obj: Any) -> None:
    write_atomic(path, json.dumps(obj, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class ClientError(Exception):
    """4xx: never retried."""


class ServerError(Exception):
    """5xx: retried."""


def _is_retryable(exc: BaseException) -> bool:
    return isinstance(exc, (httpx.TransportError, ServerError))


def _log_retry(state: RetryCallState) -> None:
    exc = state.outcome.exception() if state.outcome else None
    log.warning("retry %d/%s after %s: %s", state.attempt_number, "5", type(exc).__name__, exc)


def _check_status(resp: httpx.Response) -> None:
    if 400 <= resp.status_code < 500:
        raise ClientError(f"HTTP {resp.status_code} for {resp.request.url}")
    if resp.status_code >= 500:
        raise ServerError(f"HTTP {resp.status_code} for {resp.request.url}")


class Fetcher:
    """HTTP downloads with per-host concurrency limits, retries, resume and a manifest."""

    def __init__(self, cfg: dict[str, Any], *, force: bool = False) -> None:
        self.cfg = cfg
        self.force = force
        self.data_dir = Path(cfg["data_dir"])
        self.manifest = Manifest(self.data_dir / "MANIFEST.jsonl")
        self.client = httpx.Client(
            headers={"User-Agent": cfg["user_agent"]},
            timeout=httpx.Timeout(cfg.get("timeout_seconds", 60), connect=30),
            follow_redirects=True,
        )
        n = int(cfg.get("max_concurrency_per_host", 4))
        self._host_sem: dict[str, threading.Semaphore] = defaultdict(lambda: threading.Semaphore(n))
        self._retry = retry(
            retry=retry_if_exception(_is_retryable),
            stop=stop_after_attempt(int(cfg.get("retry_attempts", 5))),
            wait=wait_exponential_jitter(initial=1, max=60),
            before_sleep=_log_retry,
            reraise=True,
        )

    def close(self) -> None:
        self.client.close()

    # -- small requests ----------------------------------------------------

    def get_text(self, url: str) -> str:
        return self._retry(self._get_text)(url)

    def _get_text(self, url: str) -> str:
        with self._host_sem[httpx.URL(url).host]:
            resp = self.client.get(url)
        _check_status(resp)
        return resp.text

    def head(self, url: str) -> httpx.Response:
        return self._retry(self._head)(url)

    def _head(self, url: str) -> httpx.Response:
        with self._host_sem[httpx.URL(url).host]:
            resp = self.client.head(url)
        _check_status(resp)
        return resp

    def content_length(self, url: str) -> int | None:
        try:
            cl = self.head(url).headers.get("content-length")
        except ClientError:
            return None
        return int(cl) if cl else None

    # -- downloads ---------------------------------------------------------

    def download(
        self,
        target: str,
        url: str,
        path: Path,
        params: dict[str, Any] | None = None,
        *,
        expected_size: int | None = None,
    ) -> ManifestEntry | None:
        """Stream `url` to `path` (.part then atomic rename). Returns the manifest entry, or
        None when the file was already present with the right size (skipped)."""
        params = params or {}
        if not self.force and path.exists():
            size = path.stat().st_size
            known = self.manifest.get(path)
            if known is not None and known.bytes == size:
                log.debug("skip (manifest) %s", path)
                return None
            if expected_size is None:
                expected_size = self.content_length(url)
            if expected_size is not None and expected_size == size:
                log.debug("skip (content-length) %s", path)
                entry = self._entry(target, url, path, params)
                self.manifest.record(entry)
                return None
            log.info("size mismatch for %s (have %d, want %s); re-downloading", path, size, expected_size)

        self._retry(self._download_once)(url, path)
        entry = self._entry(target, url, path, params)
        self.manifest.record(entry)
        log.info("fetched %s (%s bytes)", path, f"{entry.bytes:,}")
        return entry

    def _entry(self, target: str, url: str, path: Path, params: dict[str, Any]) -> ManifestEntry:
        return ManifestEntry(
            target=target,
            url=url,
            path=str(path),
            bytes=path.stat().st_size,
            sha256=sha256_file(path),
            fetched_at=now_iso(),
            params=params,
        )

    def _download_once(self, url: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        part = path.with_name(path.name + ".part")
        resume_from = part.stat().st_size if part.exists() and not self.force else 0
        headers = {"Range": f"bytes={resume_from}-"} if resume_from else {}
        with self._host_sem[httpx.URL(url).host]:
            with self.client.stream("GET", url, headers=headers) as resp:
                if resume_from and resp.status_code != 206:
                    resume_from = 0  # server ignored the range: start over
                _check_status(resp)
                mode = "ab" if resume_from else "wb"
                with part.open(mode) as f:
                    for chunk in resp.iter_bytes(1 << 20):
                        f.write(chunk)
                expected = resp.headers.get("content-length")
                if expected is not None and resp.status_code == 200:
                    got = part.stat().st_size
                    if got != int(expected):
                        raise httpx.TransportError(f"short read: {got} of {expected} bytes for {url}")
        os.replace(part, path)


def parse_hrefs(html: str) -> list[str]:
    """Extract href targets from an Apache/nginx autoindex page without pulling in a parser."""
    import re

    return re.findall(r'href="([^"]+)"', html)
