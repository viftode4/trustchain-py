"""Zero-config TrustChain sidecar SDK.

Usage::

    import trustchain
    trustchain.init()
    # All HTTP calls are now trust-protected.

Or with full control::

    with trustchain.TrustChainSidecar(name="test") as tc:
        print(tc.pubkey)
        print(tc.trust_score("deadbeef..."))
"""

from __future__ import annotations

import asyncio
import atexit
import functools
import inspect
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# Early-access public seed node. Not production-scale yet — will be
# replaced with a domain and additional nodes as the network grows.
DEFAULT_SEED_NODES: list[str] = ["http://5.161.255.238:8202"]

# Global singleton
_instance: TrustChainSidecar | None = None
_lock = threading.Lock()

# urllib opener that bypasses HTTP_PROXY (prevents infinite loop when
# our sidecar IS the proxy)
_direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _binary_name() -> str:
    return "trustchain-node.exe" if _is_windows() else "trustchain-node"


def _generate_name() -> str:
    """Generate a default sidecar name from the script name + PID."""
    main = sys.modules.get("__main__")
    if main and hasattr(main, "__file__") and main.__file__:
        stem = Path(main.__file__).stem
    else:
        stem = "python"
    return f"{stem}-{os.getpid()}"


_GITHUB_REPO = "viftode4/trustchain"


def _platform_artifact() -> str:
    """Map current platform to GitHub release artifact name."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalize architecture
    arch_map = {
        "x86_64": "x64", "amd64": "x64",
        "aarch64": "arm64", "arm64": "arm64",
    }
    arch = arch_map.get(machine)
    if not arch:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    if system == "linux":
        return f"trustchain-node-linux-{arch}.tar.gz"
    elif system == "darwin":
        return f"trustchain-node-macos-{arch}.tar.gz"
    elif system == "windows":
        return f"trustchain-node-windows-{arch}.zip"
    else:
        raise RuntimeError(f"Unsupported platform: {system}")


def _download_binary() -> str:
    """Download the trustchain-node binary from GitHub Releases.

    Returns the path to the downloaded binary.
    """
    artifact = _platform_artifact()
    bin_dir = Path.home() / ".trustchain" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    dest = bin_dir / _binary_name()

    # Fetch latest release info from GitHub API
    api_url = f"https://api.github.com/repos/{_GITHUB_REPO}/releases/latest"
    print(f"[trustchain] Downloading binary for {platform.system()}-{platform.machine()}...")

    try:
        req = urllib.request.Request(
            api_url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "trustchain-py"},
        )
        resp = _direct_opener.open(req, timeout=15)
        release = json.loads(resp.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Failed to fetch release info: {exc}") from exc

    version = release.get("tag_name", "unknown")

    # Find the matching asset
    download_url = None
    for asset in release.get("assets", []):
        if asset["name"] == artifact:
            download_url = asset["browser_download_url"]
            break

    if not download_url:
        available = [a["name"] for a in release.get("assets", [])]
        raise RuntimeError(
            f"No release artifact '{artifact}' found in {version}.\n"
            f"Available: {available}"
        )

    # Download the archive
    import tempfile
    try:
        req = urllib.request.Request(download_url, headers={"User-Agent": "trustchain-py"})
        resp = _direct_opener.open(req, timeout=120)
        archive_data = resp.read()
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Failed to download {download_url}: {exc}") from exc

    # Extract the binary
    import io
    if artifact.endswith(".tar.gz"):
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as tf:
            # Find the binary inside the archive
            for member in tf.getmembers():
                if member.name.endswith("trustchain-node") and member.isfile():
                    with tf.extractfile(member) as f:  # type: ignore[union-attr]
                        dest.write_bytes(f.read())
                    break
            else:
                raise RuntimeError("trustchain-node not found in archive")
    elif artifact.endswith(".zip"):
        import zipfile
        with zipfile.ZipFile(io.BytesIO(archive_data)) as zf:
            for name in zf.namelist():
                if name.endswith("trustchain-node.exe"):
                    dest.write_bytes(zf.read(name))
                    break
            else:
                raise RuntimeError("trustchain-node.exe not found in archive")

    # Make executable on Unix
    if not _is_windows():
        dest.chmod(0o755)

    print(f"[trustchain] Downloaded {version} → {dest}")
    return str(dest)


def _find_binary(explicit: str | None = None) -> str:
    """Locate the trustchain-node binary.

    Search order:
    1. Explicit path (if provided)
    2. PATH lookup
    3. ~/.trustchain/bin/
    4. Auto-download from GitHub Releases
    """
    name = _binary_name()

    # 1. Explicit
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return str(p)
        raise RuntimeError(f"Binary not found at explicit path: {explicit}")

    # 2. PATH
    found = shutil.which("trustchain-node")
    if found:
        return found

    # 3. ~/.trustchain/bin/
    home_bin = Path.home() / ".trustchain" / "bin" / name
    if home_bin.is_file():
        return str(home_bin)

    # 4. Auto-download from GitHub Releases
    return _download_binary()


def _find_free_port_base(count: int = 4) -> int:
    """Find a base port where `count` consecutive ports are all free.

    Scans 18200-19000 in steps of 4 (shuffled) so multiple sidecars
    don't collide.
    """
    import random

    candidates = list(range(18200, 19000, count))
    random.shuffle(candidates)

    for base in candidates:
        if _ports_available(base, count):
            return base

    # Fallback: let the OS pick a port and round down to a multiple of `count`
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return port - (port % count)


def _ports_available(base: int, count: int) -> bool:
    for offset in range(count):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", base + offset))
        except OSError:
            return False
    return True


class TrustChainSidecar:
    """Manages a trustchain-node sidecar process.

    Spawns the Rust binary, waits for it to be ready, and provides
    convenience methods for the HTTP API.
    """

    def __init__(
        self,
        *,
        name: str | None = None,
        endpoint: str = "http://127.0.0.1:0",
        port_base: int | None = None,
        bootstrap: str | list[str] | None = None,
        data_dir: str | None = None,
        log_level: str = "info",
        binary: str | None = None,
        auto_start: bool = True,
    ) -> None:
        self._name = name or _generate_name()
        self._endpoint = endpoint
        self._port_base = port_base or _find_free_port_base()
        self._log_level = log_level
        self._binary_path = binary
        self._data_dir = data_dir
        self._pubkey: str | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._stopped = False
        self._prev_http_proxy: str | None = None

        # Normalize bootstrap to list; default to public seed node
        if bootstrap is None:
            self._bootstrap: list[str] = list(DEFAULT_SEED_NODES)
        elif isinstance(bootstrap, str):
            self._bootstrap = [b.strip() for b in bootstrap.split(",") if b.strip()]
        else:
            self._bootstrap = list(bootstrap)

        if auto_start:
            self.start()

    # -- Properties --

    @property
    def name(self) -> str:
        return self._name

    @property
    def pubkey(self) -> str | None:
        if self._pubkey is None and self.is_running:
            try:
                st = self.status()
                self._pubkey = st.get("public_key")
            except Exception:
                pass
        return self._pubkey

    @property
    def port_base(self) -> int:
        return self._port_base

    @property
    def http_port(self) -> int:
        return self._port_base + 2

    @property
    def proxy_port(self) -> int:
        return self._port_base + 3

    @property
    def http_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.proxy_port}"

    @property
    def is_running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    # -- Lifecycle --

    def start(self, _retries: int = 2) -> None:
        """Find the binary, spawn the sidecar, wait for ready, set HTTP_PROXY.

        If the sidecar fails to start (e.g. port already taken between our
        check and the actual bind), re-allocate ports and retry up to
        ``_retries`` times.
        """
        if self.is_running:
            return

        self._stopped = False
        binary = _find_binary(self._binary_path)

        last_error: Exception | None = None
        for attempt in range(_retries + 1):
            if attempt > 0:
                # Re-allocate ports on retry (previous ones were stolen)
                self._port_base = _find_free_port_base()

            cmd = [
                binary, "sidecar",
                "--name", self._name,
                "--endpoint", self._endpoint,
                "--port-base", str(self._port_base),
                "--log-level", self._log_level,
            ]
            if self._bootstrap:
                cmd.extend(["--bootstrap", ",".join(self._bootstrap)])
            if self._data_dir:
                cmd.extend(["--data-dir", self._data_dir])

            env = os.environ.copy()
            env.pop("HTTP_PROXY", None)
            env.pop("http_proxy", None)

            kwargs: dict[str, Any] = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "env": env,
            }
            if _is_windows():
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

            self._process = subprocess.Popen(cmd, **kwargs)

            # Parse pubkey from stdout banner (non-blocking reader)
            self._start_stdout_reader()

            try:
                self._wait_ready()
                break  # Success
            except (RuntimeError, TimeoutError) as exc:
                last_error = exc
                # Kill the failed process before retrying
                try:
                    self._process.kill()
                    self._process.wait(timeout=2)
                except Exception:
                    pass
                self._process = None
                if attempt < _retries:
                    continue
                raise last_error

        # Set HTTP_PROXY so all outbound HTTP goes through the sidecar
        self._prev_http_proxy = os.environ.get("HTTP_PROXY")
        os.environ["HTTP_PROXY"] = self.proxy_url
        os.environ["http_proxy"] = self.proxy_url

        # Register cleanup
        atexit.register(self.stop)
        try:
            signal.signal(signal.SIGTERM, lambda *_: self.stop())
        except (OSError, ValueError):
            pass  # fails in non-main thread or on some platforms

    def _start_stdout_reader(self) -> None:
        """Read stdout in a background thread to capture the public key."""
        def _reader() -> None:
            assert self._process is not None
            assert self._process.stdout is not None
            for raw_line in self._process.stdout:
                line = raw_line.decode("utf-8", errors="replace").strip()
                # Look for "Public key: <hex>"
                m = re.search(r"Public key:\s*([0-9a-fA-F]{64})", line)
                if m:
                    self._pubkey = m.group(1)

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

    def _wait_ready(self, timeout: float = 10.0) -> None:
        """Poll GET /healthz (with /status fallback) until the sidecar responds."""
        healthz_url = f"{self.http_url}/healthz"
        status_url = f"{self.http_url}/status"
        deadline = time.monotonic() + timeout
        delay = 0.1  # start at 100ms

        while time.monotonic() < deadline:
            # Check if the process died
            if self._process is not None and self._process.poll() is not None:
                stderr = ""
                if self._process.stderr:
                    # Bounded read — never block indefinitely.  On some OS
                    # configurations (e.g. Windows CREATE_NEW_PROCESS_GROUP)
                    # a child holding stderr open makes .read() hang forever.
                    try:
                        stderr = self._process.stderr.read(8192).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        stderr = "(stderr unreadable)"
                raise RuntimeError(
                    f"Sidecar process exited with code {self._process.returncode}.\n"
                    f"stderr: {stderr}"
                )

            # Try /healthz first (lighter, faster), fall back to /status.
            for url in (healthz_url, status_url):
                try:
                    req = urllib.request.Request(url, method="GET")
                    resp = _direct_opener.open(req, timeout=2)
                    if resp.status == 200:
                        data = json.loads(resp.read().decode())
                        if self._pubkey is None:
                            self._pubkey = data.get("public_key")
                        return
                except (urllib.error.URLError, OSError, json.JSONDecodeError):
                    pass

            time.sleep(delay)
            delay = min(delay * 1.5, 1.0)

        raise TimeoutError(
            f"Sidecar did not become ready within {timeout}s "
            f"(checked {healthz_url})"
        )

    def stop(self) -> None:
        """Stop the sidecar process and restore HTTP_PROXY. Idempotent."""
        if self._stopped:
            return
        self._stopped = True

        # Restore HTTP_PROXY
        if self._prev_http_proxy is not None:
            os.environ["HTTP_PROXY"] = self._prev_http_proxy
            os.environ["http_proxy"] = self._prev_http_proxy
        else:
            os.environ.pop("HTTP_PROXY", None)
            os.environ.pop("http_proxy", None)

        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self._process.kill()
                    self._process.wait(timeout=2)
                except OSError:
                    pass
            self._process = None

    # -- Context manager --

    def __enter__(self) -> TrustChainSidecar:
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop()

    # -- HTTP API helpers --

    def _get(self, path: str) -> Any:
        url = f"{self.http_url}{path}"
        req = urllib.request.Request(url, method="GET")
        try:
            resp = _direct_opener.open(req, timeout=5)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            raise RuntimeError(f"GET {path} failed ({exc.code}): {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GET {path} failed: {exc.reason}") from exc

    def _post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        url = f"{self.http_url}{path}"
        data = json.dumps(body or {}).encode()
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            resp = _direct_opener.open(req, timeout=10)
            return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            raise RuntimeError(f"POST {path} failed ({exc.code}): {body_text}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"POST {path} failed: {exc.reason}") from exc

    def status(self) -> dict[str, Any]:
        """GET /status — node status including public_key, block_count, peer_count."""
        return self._get("/status")

    def trust_score(self, pubkey: str) -> float:
        """GET /trust/{pubkey} — compute trust score for a peer."""
        data = self._get(f"/trust/{pubkey}")
        # Response may be {"trust_score": 0.85} or just a number
        if isinstance(data, (int, float)):
            return float(data)
        return float(data.get("trust_score", data.get("score", 0.0)))

    def discover(
        self,
        capability: str,
        *,
        min_trust: float | None = None,
        max_results: int | None = None,
    ) -> list[dict[str, Any]]:
        """GET /discover — P2P capability discovery with fan-out to peers."""
        params = [f"capability={urllib.parse.quote(capability)}"]
        if min_trust is not None:
            params.append(f"min_trust={min_trust}")
        if max_results is not None:
            params.append(f"max_results={max_results}")
        return self._get(f"/discover?{'&'.join(params)}")

    def peers(self) -> list[dict[str, Any]]:
        """GET /peers — list known peers."""
        return self._get("/peers")

    def propose(self, counterparty: str, transaction: dict[str, Any] | None = None) -> dict[str, Any]:
        """POST /propose — initiate a bilateral proposal with a peer."""
        body: dict[str, Any] = {"counterparty_pubkey": counterparty}
        if transaction:
            body["transaction"] = transaction
        return self._post("/propose", body)

    # -- Delegation API --
    # These endpoints are supported by both the Rust sidecar and Python TrustChainNode.

    def delegate(
        self,
        delegate_pubkey: str,
        scope: list[str] | None = None,
        max_depth: int = 0,
        ttl_seconds: float = 3600.0,
    ) -> dict[str, Any]:
        """POST /delegate — create a delegation for another identity."""
        return self._post("/delegate", {
            "delegate_pubkey": delegate_pubkey,
            "scope": scope or [],
            "max_depth": max_depth,
            "ttl_seconds": int(ttl_seconds),
        })

    def revoke(self, delegation_id: str) -> dict[str, Any]:
        """POST /revoke — revoke a delegation."""
        return self._post("/revoke", {
            "delegation_id": delegation_id,
        })

    def delegations(self, pubkey: str | None = None) -> list[dict[str, Any]]:
        """GET /delegations/{pubkey} — list delegations for a pubkey."""
        pk = pubkey or self.pubkey
        return self._get(f"/delegations/{pk}")

    def delegation(self, delegation_id: str) -> dict[str, Any]:
        """GET /delegation/{id} — get a specific delegation."""
        return self._get(f"/delegation/{delegation_id}")

    def identity(self, pubkey: str) -> dict[str, Any]:
        """GET /identity/{pubkey} — resolve identity (follow succession chain)."""
        return self._get(f"/identity/{pubkey}")

    def register_peer(self, pubkey: str, address: str) -> dict[str, Any]:
        """POST /peers — register a peer."""
        return self._post("/peers", {"pubkey": pubkey, "address": address})

    def healthz(self) -> dict[str, Any]:
        """GET /healthz — health check."""
        return self._get("/healthz")

    def chain(self, pubkey: str | None = None) -> list[dict[str, Any]]:
        """GET /chain/{pubkey} — get the full chain for a pubkey."""
        pk = pubkey or self.pubkey
        data = self._get(f"/chain/{pk}")
        if isinstance(data, dict):
            return data.get("blocks", [])
        return data

    def block(self, pubkey: str, seq: int) -> dict[str, Any] | None:
        """GET /block/{pubkey}/{seq} — get a specific block."""
        try:
            data = self._get(f"/block/{pubkey}/{seq}")
            return data.get("block", data) if isinstance(data, dict) else data
        except Exception:
            return None

    def crawl(self, pubkey: str, start_seq: int = 1) -> list[dict[str, Any]]:
        """GET /crawl/{pubkey} — crawl blocks from a peer."""
        data = self._get(f"/crawl/{pubkey}?start_seq={start_seq}")
        if isinstance(data, dict):
            return data.get("blocks", [])
        return data

    def receive_proposal(self, block: dict[str, Any]) -> dict[str, Any]:
        """POST /receive_proposal — receive a proposal block from a peer."""
        return self._post("/receive_proposal", block)

    def receive_agreement(self, block: dict[str, Any]) -> dict[str, Any]:
        """POST /receive_agreement — receive an agreement block from a peer."""
        return self._post("/receive_agreement", block)

    def accept_delegation(self, proposal_block: dict[str, Any]) -> dict[str, Any]:
        """POST /accept_delegation — accept a delegation proposal."""
        return self._post("/accept_delegation", {"proposal_block": proposal_block})

    def accept_succession(self, proposal_block: dict[str, Any]) -> dict[str, Any]:
        """POST /accept_succession — accept a succession proposal."""
        return self._post("/accept_succession", {"proposal_block": proposal_block})

    def metrics(self) -> str:
        """GET /metrics — Prometheus metrics (returns raw text)."""
        url = f"{self.http_url}/metrics"
        req = urllib.request.Request(url, method="GET")
        try:
            resp = _direct_opener.open(req, timeout=5)
            return resp.read().decode()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            raise RuntimeError(f"GET /metrics failed ({exc.code}): {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GET /metrics failed: {exc.reason}") from exc

    def my_delegation(self) -> dict[str, Any] | None:
        """Check if this node is a delegate.

        Falls back gracefully — returns None if the endpoint is unavailable
        (e.g. when running against the Rust sidecar).
        """
        try:
            status = self.status()
            if status.get("is_delegated"):
                return {
                    "is_delegated": True,
                    "root_identity": status.get("root_identity"),
                }
            return None
        except Exception:
            return None

    # -- Repr --

    def __repr__(self) -> str:
        state = "running" if self.is_running else "stopped"
        return (
            f"TrustChainSidecar(name={self._name!r}, "
            f"port_base={self._port_base}, {state})"
        )


# === Module-level convenience API ===


def init(
    *,
    name: str | None = None,
    endpoint: str = "http://127.0.0.1:0",
    port_base: int | None = None,
    bootstrap: str | list[str] | None = None,
    data_dir: str | None = None,
    log_level: str = "info",
    binary: str | None = None,
) -> TrustChainSidecar:
    """Start the TrustChain sidecar (idempotent singleton).

    Call once at the top of your script::

        import trustchain
        trustchain.init()
        # done — all HTTP calls are now trust-protected
    """
    global _instance
    with _lock:
        if _instance is not None and _instance.is_running:
            return _instance
        _instance = TrustChainSidecar(
            name=name,
            endpoint=endpoint,
            port_base=port_base,
            bootstrap=bootstrap,
            data_dir=data_dir,
            log_level=log_level,
            binary=binary,
        )
        return _instance


def protect(**kwargs: Any) -> TrustChainSidecar:
    """Alias for init() that communicates intent: protect all HTTP calls."""
    return init(**kwargs)


def init_delegate(
    *,
    parent_url: str,
    scope: list[str] | None = None,
    ttl_seconds: float = 3600.0,
    **kwargs: Any,
) -> TrustChainSidecar:
    """Start a TrustChain sidecar as a delegated agent.

    Starts the sidecar, then requests a delegation certificate from the parent.

    Args:
        parent_url: HTTP URL of the parent sidecar (e.g. "http://127.0.0.1:18202")
        scope: Allowed interaction types (empty = wildcard)
        ttl_seconds: Delegation TTL (default 1 hour)
        **kwargs: Passed to init() (name, port_base, etc.)
    """
    sidecar = init(**kwargs)

    # Request delegation from parent
    req = urllib.request.Request(
        f"{parent_url}/delegate",
        data=json.dumps({
            "delegate_pubkey": sidecar.pubkey,
            "scope": scope or [],
            "ttl_seconds": ttl_seconds,
        }).encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = _direct_opener.open(req, timeout=10)
        data = json.loads(resp.read().decode())
        if not data.get("accepted"):
            raise RuntimeError(f"Delegation rejected: {data.get('error', 'unknown')}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Failed to request delegation from {parent_url}: {exc}") from exc

    # Complete the bilateral handshake: accept the delegation on the delegate sidecar.
    proposal_block = data.get("proposal_block") or data.get("block")
    if proposal_block:
        sidecar.accept_delegation(proposal_block)

    return sidecar


def download_binary() -> str:
    """Explicitly download the trustchain-node binary.

    Useful for Docker images, CI, or pre-provisioning environments.
    Returns the path to the downloaded binary.
    """
    return _download_binary()


def with_trust(
    fn: Any = None,
    *,
    name: str | None = None,
    bootstrap: str | list[str] | None = None,
    log_level: str = "info",
    binary: str | None = None,
) -> Any:
    """Decorator that wraps a function with TrustChain sidecar lifecycle.

    Starts the sidecar before the function runs and sets ``HTTP_PROXY``
    so all outbound HTTP calls are trust-protected. Cleanup is handled
    automatically via ``atexit``.

    Can be used with or without arguments::

        @with_trust
        def main():
            ...

        @with_trust(name="my-agent")
        def main():
            ...

        @with_trust(name="async-agent")
        async def main():
            ...
    """

    def decorator(func: Any) -> Any:
        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            sidecar = init(
                name=name, bootstrap=bootstrap,
                log_level=log_level, binary=binary,
            )
            _print_banner(sidecar)
            return func(*args, **kwargs)

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            sidecar = init(
                name=name, bootstrap=bootstrap,
                log_level=log_level, binary=binary,
            )
            _print_banner(sidecar)
            return await func(*args, **kwargs)

        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    # Support both @with_trust and @with_trust(name="x")
    if fn is not None:
        return decorator(fn)
    return decorator


def _print_banner(sidecar: TrustChainSidecar) -> None:
    """Print a startup banner with sidecar info."""
    pk = sidecar.pubkey or "pending..."
    print(
        f"[trustchain] Sidecar ready\n"
        f"  pubkey:    {pk}\n"
        f"  http:      {sidecar.http_url}\n"
        f"  proxy:     {sidecar.proxy_url}\n"
        f"  dashboard: {sidecar.http_url}/dashboard"
    )
