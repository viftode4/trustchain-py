"""TrustChain CLI — command-line interface for the TrustChain sidecar.

Entry point: ``trustchain`` (installed via pyproject.toml ``[project.scripts]``).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path


def cmd_wrap(args: argparse.Namespace) -> None:
    """Download binary if needed, then exec the user's command with trust proxy."""
    from trustchain.sidecar import _find_binary

    binary = _find_binary()

    # Build sidecar launch command
    sidecar_cmd = [binary, "sidecar", "--name", args.name or "cli-wrap"]
    if args.bootstrap:
        sidecar_cmd.extend(["--bootstrap", args.bootstrap])

    # Launch sidecar, wait for ready, then exec the user command
    env = os.environ.copy()
    env.pop("HTTP_PROXY", None)
    env.pop("http_proxy", None)

    sidecar_proc = subprocess.Popen(
        sidecar_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    # Wait for sidecar to be ready (poll /healthz)
    import urllib.request
    import urllib.error

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    # Default port base is 18200, HTTP = +2, proxy = +3
    http_port = 18202
    proxy_port = 18203
    deadline = time.monotonic() + 15.0
    ready = False
    while time.monotonic() < deadline:
        if sidecar_proc.poll() is not None:
            stderr = sidecar_proc.stderr.read(4096).decode() if sidecar_proc.stderr else ""
            print(f"[trustchain] Sidecar exited early: {stderr}", file=sys.stderr)
            sys.exit(1)
        try:
            resp = opener.open(f"http://127.0.0.1:{http_port}/healthz", timeout=2)
            if resp.status == 200:
                ready = True
                break
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(0.2)

    if not ready:
        sidecar_proc.kill()
        print("[trustchain] Sidecar did not become ready in time.", file=sys.stderr)
        sys.exit(1)

    # Set proxy and run the user's command
    env = os.environ.copy()
    env["HTTP_PROXY"] = f"http://127.0.0.1:{proxy_port}"
    env["http_proxy"] = f"http://127.0.0.1:{proxy_port}"

    try:
        result = subprocess.run(args.command, env=env)
        sys.exit(result.returncode)
    finally:
        sidecar_proc.terminate()
        try:
            sidecar_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            sidecar_proc.kill()


def cmd_status(args: argparse.Namespace) -> None:
    """Query a running sidecar's status."""
    import urllib.request
    import urllib.error

    port = args.port or 18202
    url = f"http://127.0.0.1:{port}/status"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    try:
        resp = opener.open(url, timeout=5)
        data = json.loads(resp.read().decode())
        print(json.dumps(data, indent=2))
    except urllib.error.URLError:
        print(f"[trustchain] No sidecar found at port {port}.", file=sys.stderr)
        sys.exit(1)


def cmd_download(args: argparse.Namespace) -> None:
    """Explicitly download the trustchain-node binary."""
    from trustchain.sidecar import download_binary

    path = download_binary()
    print(f"[trustchain] Binary ready at: {path}")


def cmd_demo(args: argparse.Namespace) -> None:
    """Spin up a multi-agent demo with live trust visualization."""
    from trustchain.sidecar import TrustChainSidecar, _find_binary, _direct_opener

    # Ensure binary is available
    _find_binary()

    print("[trustchain] Starting demo with 3 agents...")
    agents: list[TrustChainSidecar] = []

    try:
        # Start 3 agents
        for i, name in enumerate(["alice", "bob", "carol"]):
            agent = TrustChainSidecar(name=name, log_level="warn")
            agents.append(agent)
            print(f"  {name}: pubkey={agent.pubkey or 'pending'}, http={agent.http_url}")

        # Cross-register as peers
        for a in agents:
            for b in agents:
                if a is not b and b.pubkey:
                    try:
                        a.register_peer(b.pubkey, b.http_url)
                    except Exception:
                        pass

        # Open dashboard for first agent
        dashboard_url = f"{agents[0].http_url}/dashboard"
        print(f"\n[trustchain] Dashboard: {dashboard_url}")
        webbrowser.open(dashboard_url)

        # Run interaction loop
        print("[trustchain] Running interactions (Ctrl+C to stop)...")
        round_num = 0
        while True:
            round_num += 1
            for i, a in enumerate(agents):
                b = agents[(i + 1) % len(agents)]
                if b.pubkey:
                    try:
                        a.propose(b.pubkey, {"type": "demo", "round": round_num})
                    except Exception:
                        pass

            # Print trust scores
            if round_num % 5 == 0 and agents[0].pubkey:
                for a in agents:
                    scores = []
                    for b in agents:
                        if a is not b and b.pubkey:
                            try:
                                s = a.trust_score(b.pubkey)
                                scores.append(f"{b.name}={s:.3f}")
                            except Exception:
                                scores.append(f"{b.name}=?")
                    print(f"  {a.name} trusts: {', '.join(scores)}")

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[trustchain] Stopping demo...")
    finally:
        for agent in agents:
            agent.stop()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="trustchain",
        description="TrustChain CLI — decentralized trust for agents",
    )
    sub = parser.add_subparsers(dest="command")

    # wrap
    p_wrap = sub.add_parser("wrap", help="Run a command with trust proxy")
    p_wrap.add_argument("command", nargs=argparse.REMAINDER, help="Command to run")
    p_wrap.add_argument("--name", help="Sidecar name")
    p_wrap.add_argument("--bootstrap", help="Bootstrap peer addresses")
    p_wrap.set_defaults(func=cmd_wrap)

    # status
    p_status = sub.add_parser("status", help="Query running sidecar status")
    p_status.add_argument("--port", type=int, help="HTTP port (default: 18202)")
    p_status.set_defaults(func=cmd_status)

    # download
    p_download = sub.add_parser("download", help="Download trustchain-node binary")
    p_download.set_defaults(func=cmd_download)

    # demo
    p_demo = sub.add_parser("demo", help="Run multi-agent trust demo")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
