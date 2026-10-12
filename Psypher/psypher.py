"""Compatibility entrypoint. The destructive 1.x program is retired.

Samples and config.cfg alongside this file are never scanned on startup.
The original implementation remains available in Git history.
"""


def main():
    import sys
    from pathlib import Path

    if sys.version_info < (3, 12):
        print("Psypher 2.0 için Python 3.12 veya üstü gerekli.")
        return 2
    # Prefer the real src package over this legacy file with the same name.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    try:
        from psypher.cli import main as run
    except ModuleNotFoundError:
        print("Önce proje kökünde bağımlılıkları kurun: python -m pip install -r requirements.txt")
        return 2
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
