"""PyInstaller entrypoint (console mode, no embedded secrets)."""

from psypher.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
