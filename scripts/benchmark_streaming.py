"""Opt-in real-file streaming/memory validation. Never opens repository fixtures."""

import argparse
import hashlib
import json
import os
import secrets
import tempfile
import time
from pathlib import Path

from psypher import crypto
from psypher.vault import Vault


def rss_bytes():
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel = ctypes.WinDLL("kernel32")
        psapi = ctypes.WinDLL("psapi")
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        if not psapi.GetProcessMemoryInfo(
            kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            raise ctypes.WinError()
        return counters.WorkingSetSize
    if Path("/proc/self/status").exists():
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    import sys

    return peak if sys.platform == "darwin" else peak * 1024


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(crypto.CHUNK_SIZE):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gib", type=int, default=10)
    parser.add_argument("--report", type=Path, default=Path(".validation/streaming-10gib.json"))
    args = parser.parse_args()
    if args.gib < 1:
        parser.error("--gib must be >= 1")
    size = args.gib * 1024**3
    started = time.monotonic()
    measurements = {}
    with tempfile.TemporaryDirectory(prefix="psypher-stream-check-") as directory:
        temporary = Path(directory)
        source = temporary / "generated-zero-file.bin"
        with source.open("wb") as target:
            target.truncate(size)
        recovery = secrets.token_bytes(32)
        password = secrets.token_urlsafe(32)
        root = temporary / "vault"
        Vault.create(root, password, recovery, recovery)
        with Vault.open(root, password) as vault:
            # KDF's separate 256 MiB cost is excluded from streaming RSS growth.
            baseline = rss_bytes()
            peak = baseline
            last = -1

            def event(name, done, total):
                nonlocal peak, last
                if done // (64 * 1024**2) != last:
                    last = done // (64 * 1024**2)
                    peak = max(peak, rss_bytes())
                    if done and done % (1024**3) == 0:
                        print(f"Streaming {done // 1024**3}/{args.gib} GiB", flush=True)

            step = time.monotonic()
            result = vault.add([source], event)
            measurements["add_and_readback_seconds"] = round(time.monotonic() - step, 3)
            assert result["bytes"] == size
            step = time.monotonic()
            vault.export(temporary / "export", event=event)
            measurements["verified_export_seconds"] = round(time.monotonic() - step, 3)
            exported = temporary / "export" / source.name
            assert digest(exported) == vault.catalog["files"][source.name]["sha256"]
            assert source.stat().st_size == exported.stat().st_size == size
            growth = peak - baseline
            assert growth < 64 * 1024**2, f"Streaming RSS grew by {growth} bytes"
            measurements.update(
                bytes=size,
                baseline_rss_bytes=baseline,
                sampled_peak_rss_bytes=peak,
                streaming_rss_growth_bytes=growth,
                kdf_memory_bytes=crypto.MEMLIMIT,
                source_preserved=True,
                export_sha256_matches=True,
                bounded_memory=True,
            )
    measurements["total_seconds"] = round(time.monotonic() - started, 3)
    measurements["temporary_files_removed"] = True
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(measurements, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(measurements, indent=2), flush=True)


if __name__ == "__main__":
    main()
