# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jigokuraku01
# Additional author attribution terms: see ATTRIBUTION.md.
"""Command line entry point for SovaGrid Connect."""

from __future__ import annotations

import argparse
import sys
import webbrowser

from . import __version__
from .core import ConnectionOptions, Tunnel, TunnelError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sovagrid-connect",
        description="Open the full SovaGrid web panel through a verified SSH tunnel.",
    )
    parser.add_argument("--version", action="version", version=f"SovaGrid Connect {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    connect = commands.add_parser("connect", help="connect in the foreground; Ctrl+C disconnects")
    connect.add_argument("--host", required=True, help="SSH host running the SovaGrid panel")
    connect.add_argument("--user", required=True, help="SSH login on that host")
    connect.add_argument("--port", type=int, default=22)
    connect.add_argument("--jump-host", help="optional SSH jump host")
    connect.add_argument("--jump-user", help="SSH login on jump host (defaults to --user)")
    connect.add_argument("--jump-port", type=int, default=22)
    connect.add_argument("--identity", help="target SSH private key path")
    connect.add_argument("--jump-identity", help="jump-host SSH private key path")
    connect.add_argument("--host-key-alias", help="known_hosts name for the target (useful for multiple reverse tunnels)")
    connect.add_argument("--jump-host-key-alias", help="known_hosts name for the jump host")
    connect.add_argument("--local-port", type=int, default=0, help="0 chooses an unused loopback port")
    connect.add_argument("--remote-port", type=int, default=8766, help="panel port on target host")
    connect.add_argument("--timeout", type=float, default=120.0)
    connect.add_argument("--no-browser", action="store_true")
    commands.add_parser("gui", help="open a graphical launcher (SSH password, key, or agent)")
    license_command = commands.add_parser("license", help="show license and author attribution")
    license_command.add_argument("--attribution", action="store_true", help="show author attribution terms")
    notices_command = commands.add_parser("third-party-licenses", help="read bundled third-party notices offline")
    notices_command.add_argument("document", nargs="?", help="document path from --list (default: INDEX.md)")
    notices_command.add_argument("--list", action="store_true", help="list all bundled notices")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "license":
        from .legal import document
        print(document("ATTRIBUTION.md" if args.attribution else "LICENSE"))
        return 0
    if args.command == "third-party-licenses":
        from .legal import third_party_document, third_party_documents
        if args.list:
            print("\n".join(third_party_documents()))
            return 0
        try:
            print(third_party_document(args.document or "INDEX.md"))
        except ValueError as exc:
            print(f"SovaGrid Connect: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.command == "gui":
        try:
            from .gui import main as gui_main

            return gui_main()
        except ImportError as exc:
            print(f"Graphical launcher unavailable: {exc}", file=sys.stderr)
            return 2
    try:
        options = ConnectionOptions(
            host=args.host,
            user=args.user,
            port=args.port,
            jump_host=args.jump_host,
            jump_user=args.jump_user,
            jump_port=args.jump_port,
            identity=args.identity,
            jump_identity=args.jump_identity,
            host_key_alias=args.host_key_alias,
            jump_host_key_alias=args.jump_host_key_alias,
            local_port=args.local_port,
            remote_port=args.remote_port,
        )
        tunnel = Tunnel(options)
        try:
            tunnel.start(timeout=args.timeout)
            print(f"SovaGrid panel: {tunnel.panel_url}")
            if not args.no_browser:
                webbrowser.open(tunnel.panel_url, new=2)
            print("Keep this window open. Press Ctrl+C to disconnect.")
            code = tunnel.wait()
            raise TunnelError(f"SSH disconnected (code {code})")
        finally:
            tunnel.close()
    except KeyboardInterrupt:
        print("\nDisconnected.")
        return 0
    except (ValueError, TunnelError, OSError) as exc:
        print(f"SovaGrid Connect: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
