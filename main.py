#!/usr/bin/env python3
"""Maze Vault — a Bitwarden-compatible password manager for Maze Linux."""
import sys

if __name__ == "__main__":
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print("Usage: maze-vault [--lang=en|tr]")
        sys.exit(0)
    if "--version" in sys.argv[1:]:
        from mazevault import __version__
        print(f"maze-vault {__version__}")
        sys.exit(0)
    from mazevault.gui.app import run
    sys.exit(run())
