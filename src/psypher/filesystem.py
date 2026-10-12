"""Restricted creation, bounded reads, link checks and OS-backed locking."""

import contextlib
import ctypes
import os
import re
import stat
from pathlib import Path
from typing import BinaryIO

import portalocker

from .errors import IntegrityError, LockedError, StorageError, UsageError

REPARSE = 0x400
_RESERVED = re.compile(r"^(CON|CONIN\$|CONOUT\$|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.I)


def absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(path))


def no_links(path: str | Path) -> Path:
    path = absolute(path)
    for part in [*reversed(path.parents), path]:
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE:
            raise StorageError("Sembolik bağlantı veya junction kullanılamaz.")
    return path


def within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def require_private_filesystem(path: Path) -> None:
    """Do not silently ignore DACLs on FAT/exFAT or unsupported network volumes."""
    if os.name != "nt":
        return
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    if path.anchor.startswith("\\\\") or kernel.GetDriveTypeW(path.anchor) == 4:
        raise StorageError("Ağ sürücülerinde kasa/sır yazımı desteklenmiyor; yerel disk seçin.")
    kernel.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    flags = wintypes.DWORD()
    if not kernel.GetVolumeInformationW(
        path.anchor, None, 0, None, None, ctypes.byref(flags), None, 0
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    if not flags.value & 8:  # FILE_PERSISTENT_ACLS
        raise StorageError("Dosya sistemi özel izinleri desteklemiyor; NTFS/ReFS konumu seçin.")


def safe_name(name: object) -> str:
    try:
        length = len(name.encode("utf-8")) if isinstance(name, str) else 0
    except UnicodeError as exc:
        raise IntegrityError("Dosya adı geçerli Unicode değil.") from exc
    if not isinstance(name, str) or not name or length > 4096:
        raise IntegrityError("Geçersiz katalog yolu.")
    for segment in name.split("/"):
        if (
            not segment
            or segment in {".", ".."}
            or segment.endswith((" ", "."))
            or _RESERVED.match(segment)
            or len(segment.encode("utf-8")) > 255
            or any(ord(c) < 32 or ord(c) == 127 or c in '<>:"\\|?*' for c in segment)
        ):
            raise IntegrityError("Güvenli olmayan dosya adı veya yol.")
    return name


def _windows_security():
    """Protected DACL: current user + SYSTEM, inherited by child files/dirs.

    Applied by CreateFile/CreateDirectory at creation, not after exposure.
    Caller must LocalFree the returned security descriptor.
    """
    from ctypes import wintypes

    class Attributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    sid_text = wintypes.LPWSTR()
    try:
        required = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        buffer = ctypes.create_string_buffer(required.value)
        if not advapi.GetTokenInformation(token, 1, buffer, required, ctypes.byref(required)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise ctypes.WinError(ctypes.get_last_error())
        descriptor = ctypes.c_void_p()
        sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid_text.value})"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
        return kernel, attributes, descriptor
    finally:
        if sid_text:
            kernel.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        kernel.CloseHandle(token)


def private_mkdir(path: Path) -> None:
    path = no_links(path)
    require_private_filesystem(path)
    if os.name != "nt":
        path.mkdir(mode=0o700)
        return
    from ctypes import wintypes

    kernel, attributes, descriptor = _windows_security()
    try:
        kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def private_parents(path: Path) -> None:
    path = no_links(path)
    missing = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent
    if not cursor.is_dir():
        raise StorageError("Hedef üst dizin bir klasör değil.")
    for directory in reversed(missing):
        private_mkdir(directory)


def private_open(path: Path) -> BinaryIO:
    path = no_links(path)
    require_private_filesystem(path)
    if os.name != "nt":
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    else:
        import msvcrt
        from ctypes import wintypes

        kernel, attributes, descriptor = _windows_security()
        try:
            kernel.CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            kernel.CreateFileW.restype = wintypes.HANDLE
            handle = kernel.CreateFileW(
                str(path), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None
            )  # GENERIC_WRITE, CREATE_NEW
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
            except BaseException:
                kernel.CloseHandle(handle)
                raise
        finally:
            kernel.LocalFree(descriptor)
    return os.fdopen(fd, "wb")


def open_read(path: Path) -> BinaryIO:
    path = no_links(path)
    # Precheck prevents FIFOs/devices from blocking open on POSIX.
    if not stat.S_ISREG(path.stat().st_mode):
        raise StorageError("Yalnızca normal dosyalar okunabilir.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        no_links(path)
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & REPARSE:
            raise StorageError("Güvenli olmayan dosya türü.")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_bounded(path: Path, limit: int) -> bytes:
    with open_read(path) as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise IntegrityError("Dosya boyut sınırı aşıldı.")
    return data


def sync_file(target: BinaryIO) -> None:
    target.flush()
    os.fsync(target.fileno())


def sync_directory(path: Path) -> None:
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_private(path: Path, data: bytes) -> None:
    with private_open(path) as target:
        target.write(data)
        sync_file(target)
    sync_directory(path.parent)


def publish(source: Path, target: Path, replace: bool = False) -> None:
    no_links(source)
    no_links(target)
    if replace:
        os.replace(source, target)
    elif os.name == "nt":
        os.rename(source, target)  # Windows rename fails if the target exists.
    else:
        # link is an atomic no-clobber publish on the same filesystem.
        os.link(source, target, follow_symlinks=False)
        source.unlink()
    sync_directory(target.parent)


def publish_directory(source: Path, target: Path) -> None:
    no_links(source)
    no_links(target)
    if target.exists():
        raise FileExistsError("Hedef zaten mevcut.")
    if os.name == "nt":
        os.rename(source, target)
    elif os.name == "posix":
        # Linux renameat2 and macOS renamex_np provide atomic no-replace.
        libc = ctypes.CDLL(None, use_errno=True)
        if hasattr(libc, "renameat2"):
            result = libc.renameat2(-100, os.fsencode(source), -100, os.fsencode(target), 1)
        elif hasattr(libc, "renamex_np"):
            result = libc.renamex_np(os.fsencode(source), os.fsencode(target), 4)
        else:
            raise StorageError("Bu sistem atomik dizin yayımlamasını desteklemiyor.")
        if result:
            raise OSError(ctypes.get_errno(), "Dizin yayımlanamadı.")
    else:
        raise StorageError("Desteklenmeyen dosya sistemi.")
    sync_directory(target.parent)


def delete_owned_tree(path: Path) -> None:
    """Only for freshly allocated random staging directories, never user inputs."""
    path = no_links(path)
    if not path.exists():
        return
    for child in path.iterdir():
        no_links(child)
        if child.is_dir():
            delete_owned_tree(child)
        else:
            child.unlink()
    path.rmdir()


def read_keyfile(path: Path) -> bytes:
    value = read_bounded(path, 32)
    if len(value) != 32:
        raise UsageError("Anahtar dosyası tam olarak 32 bayt olmalı.")
    return value


class VaultLock:
    def __init__(self, root: Path):
        self.path = no_links(root / ".lock")
        self.file = None

    def acquire(self) -> None:
        try:
            if not self.path.exists():
                try:
                    write_private(self.path, b"0")
                except FileExistsError:
                    pass
            self.file = open_read(self.path)
            portalocker.lock(self.file, portalocker.LOCK_EX | portalocker.LOCK_NB)
        except portalocker.exceptions.LockException as exc:
            self.release()
            raise LockedError("Kasa başka bir süreç veya oturum tarafından kullanılıyor.") from exc

    def release(self) -> None:
        if self.file:
            with contextlib.suppress(OSError, portalocker.exceptions.LockException):
                portalocker.unlock(self.file)
            self.file.close()
            self.file = None
