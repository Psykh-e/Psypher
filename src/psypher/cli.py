"""Turkish console and structured CLI; secret material never enters argv/env."""

from __future__ import annotations

import argparse
import contextlib
import getpass
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TransferSpeedColumn
from rich.table import Table

from . import __version__, crypto
from .errors import IntegrityError, PsypherError, UsageError
from .filesystem import no_links, private_parents, read_bounded, read_keyfile, within, write_private
from .vault import Vault

console = Console(highlight=False, markup=False)
error_console = Console(stderr=True, highlight=False, markup=False)
RECOVERY_PREFIX = b"PSYPHER-RECOVERY-V1\n"
IDLE_SECONDS = 300
SECRET_FIELDS = {
    "password",
    "new_password",
    "recovery_key",
    "recovery_confirmation",
    "new_recovery_key",
    "new_recovery_confirmation",
}


class SessionTimeout(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's message may echo unsupported secret arguments supplied by mistake.
        raise UsageError("Komut veya seçenekler geçersiz. psypher <komut> --help kullanın.")

    def parse_args(self, args=None, namespace=None):
        result = super().parse_args(args, namespace)
        for name, default in {
            "vault": None,
            "keyfile": None,
            "secrets_fd": None,
            "json": False,
            "yes": False,
        }.items():
            if not hasattr(result, name):
                setattr(result, name, default)
        return result


def parser() -> Parser:
    common = Parser(add_help=False, argument_default=argparse.SUPPRESS)
    common.add_argument("--vault", type=Path, help="Kasa/yedek klasörünün açık yolu")
    common.add_argument("--keyfile", type=Path, help="Mevcut 32 baytlık anahtar dosyası")
    common.add_argument(
        "--secrets-fd", type=int, help="Tek satır JSON sırlarını taşıyan dosya tanıtıcısı"
    )
    common.add_argument("--json", action="store_true", help="Makine tarafından okunabilir çıktı")
    common.add_argument("--yes", action="store_true", help="İşlem önizlemesini onayla")
    root = Parser(
        prog="psypher",
        description="Psypher 2.0 — yerel şifreli konsol kasası (beta)",
        parents=[common],
    )
    root.add_argument("--version", action="version", version=__version__)
    sub = root.add_subparsers(dest="command", parser_class=Parser)
    init = sub.add_parser("init", parents=[common], help="Yeni kasa oluştur")
    init.add_argument(
        "--recovery-out", required=True, type=Path, help="Ayrı kurtarma dosyası hedefi"
    )
    add = sub.add_parser(
        "add", parents=[common], help="Dosya/klasörleri değiştirmeden kasaya kopyala"
    )
    add.add_argument("paths", nargs="+", type=Path)
    add.add_argument("--dry-run", action="store_true", help="Yalnızca önizle")
    sub.add_parser("list", parents=[common], help="Şifreli kataloğu listele")
    export = sub.add_parser("export", parents=[common], help="Doğrulayarak açık dosyalar çıkar")
    export.add_argument("names", nargs="*")
    export.add_argument("--destination", required=True, type=Path)
    remove = sub.add_parser("remove", parents=[common], help="Kasadaki seçili kayıtları sil")
    remove.add_argument("names", nargs="+")
    sub.add_parser("verify", parents=[common], help="Tüm dosyaların bütünlüğünü kontrol et")
    for name, help_text in (
        ("backup", "Doğrulanmış şifreli yedek oluştur"),
        ("restore", "Şifreli yedeği yeni konuma geri yükle"),
    ):
        command = sub.add_parser(name, parents=[common], help=help_text)
        command.add_argument("--destination", required=True, type=Path)
    sub.add_parser("passwd", parents=[common], help="Parolayı değiştir; anahtar dosyasını koru")
    keyfile = sub.add_parser("keyfile", parents=[common], help="Anahtar dosyası yönetimi")
    keyfile.add_argument("action", choices=["generate", "enable", "disable"])
    keyfile.add_argument("--out", type=Path)
    keyfile.add_argument("--new-keyfile", type=Path)
    recovery = sub.add_parser(
        "recover", parents=[common], help="Kurtarma anahtarıyla erişimi yenile"
    )
    recovery.add_argument("--recovery-in", type=Path)
    recovery.add_argument("--recovery-out", required=True, type=Path)
    recovery.add_argument("--new-keyfile", type=Path)
    migrate = sub.add_parser(
        "migrate", parents=[common], help="Eski Fernet dosyalarını salt okunur taşı"
    )
    migrate.add_argument("paths", nargs="+", type=Path)
    migrate.add_argument("--legacy-key", required=True, type=Path)
    sub.add_parser("doctor", parents=[common], help="Gerçek güvenlik durumunu göster")
    return root


def _read_secrets(fd: int | None) -> dict:
    if fd is None:
        return {}
    if fd < 0:
        raise UsageError("Geçersiz sır dosyası tanıtıcısı.")
    with os.fdopen(os.dup(fd), "rb") as channel:
        data = channel.readline(8193)
    try:
        value = crypto.parse_json(data, 8192)
    except IntegrityError as exc:
        raise UsageError("Sır kanalındaki JSON geçersiz veya boyut sınırını aşıyor.") from exc
    if set(value) - SECRET_FIELDS or any(not isinstance(v, str) for v in value.values()):
        raise UsageError("Sır kanalı yalnızca belgelenmiş metin alanlarını kabul eder.")
    try:
        for secret in value.values():
            secret.encode("utf-8")
    except UnicodeError as exc:
        raise UsageError("Sır kanalında geçersiz Unicode var.") from exc
    return value


def _password(data: dict, field: str = "password", new: bool = False) -> str:
    if field in data:
        result = data[field]
    elif sys.stdin.isatty():
        label = "Yeni parola" if new else "Kasa parolası"
        result = getpass.getpass(label + ": ")
        if new and not hmac.compare_digest(
            result.encode(), getpass.getpass("Parolayı tekrarla: ").encode()
        ):
            raise UsageError("Parolalar eşleşmiyor.")
    else:
        raise UsageError(f"Etkileşimsiz kullanımda --secrets-fd üzerinden {field} gerekli.")
    if new:
        crypto.validate_password(result)
    return result


def _hex_key(value: str) -> bytes:
    try:
        if len(value) != 64:
            raise ValueError()
        result = bytes.fromhex(value)
        if len(result) != 32:
            raise ValueError()
        return result
    except ValueError as exc:
        raise UsageError("Kurtarma anahtarı 64 onaltılık karakter olmalı.") from exc


def read_recovery(path: Path) -> bytes:
    data = read_bounded(path, len(RECOVERY_PREFIX) + 65)
    if not data.startswith(RECOVERY_PREFIX):
        raise UsageError("Kurtarma dosyası biçimi geçersiz.")
    try:
        return _hex_key(data[len(RECOVERY_PREFIX) :].decode("ascii").strip())
    except UnicodeError as exc:
        raise UsageError("Kurtarma dosyası biçimi geçersiz.") from exc


def _outside_secret(path: Path, vault: Path | None) -> Path:
    path = no_links(path)
    if vault is not None and within(path, no_links(vault)):
        raise UsageError("Kurtarma/anahtar dosyası kasanın dışında saklanmalı.")
    if path.exists():
        raise UsageError("Sır dosyası hedefi zaten mevcut; yeni bir konum seçin.")
    private_parents(path.parent)
    return path


def _new_recovery(path: Path, vault: Path, data: dict, rotate: bool = False) -> tuple[bytes, bytes]:
    field = "new_recovery_key" if rotate else "recovery_key"
    confirmation_field = "new_recovery_confirmation" if rotate else "recovery_confirmation"
    if field in data:
        key = _hex_key(data[field])
        if confirmation_field not in data:
            raise UsageError("Sır kanalında kurtarma anahtarının tekrar doğrulaması gerekli.")
        confirmation = _hex_key(data[confirmation_field])
        if not hmac.compare_digest(key, confirmation):
            raise UsageError("Kurtarma anahtarı doğrulaması eşleşmiyor.")
    elif sys.stdin.isatty():
        key = secrets.token_bytes(32)
        confirmation = None
    else:
        raise UsageError(f"Sır kanalında {field} ve {confirmation_field} gerekli.")
    path = _outside_secret(path, vault)
    write_private(path, RECOVERY_PREFIX + key.hex().encode("ascii") + b"\n")
    if confirmation is None:
        error_console.print(
            "Kurtarma dosyası kaydedildi. Kasadan ayrı tutun; bu anahtar tek başına erişim sağlar."
        )
        confirmation = _hex_key(
            getpass.getpass("Kaydedilen dosyadaki 64 karakterlik anahtarı girin: ")
        )
    if not hmac.compare_digest(key, confirmation) or not hmac.compare_digest(
        key, read_recovery(path)
    ):
        raise UsageError("Kurtarma doğrulanamadı; kasa değişmedi. Kaydedilen dosyayı kontrol edin.")
    return key, confirmation


def _confirm(args, description: str) -> None:
    if args.yes:
        return
    if not sys.stdin.isatty():
        raise UsageError("İşlem onayı için --yes gerekli.")
    error_console.print(description)
    if input("Devam etmek için EVET yazın: ").strip() != "EVET":
        raise UsageError("İşlem kullanıcı tarafından iptal edildi.")


@contextlib.contextmanager
def _progress(enabled: bool):
    if not enabled or not sys.stderr.isatty():
        yield None
        return
    with Progress(
        TextColumn("İşleniyor"),
        BarColumn(),
        TextColumn("{task.percentage:>3.0f}%"),
        TransferSpeedColumn(),
        console=error_console,
    ) as progress:
        task = progress.add_task("", total=1)
        current = None

        def event(name, done, total):
            nonlocal current
            if current != name:
                current = name
                progress.reset(task, total=max(total, 1))
            progress.update(task, completed=done)

        yield event


def execute(args, data: dict) -> dict:
    if args.command == "keyfile" and args.action == "generate":
        if args.out is None:
            raise UsageError("keyfile generate için --out gerekli.")
        write_private(_outside_secret(args.out, args.vault), secrets.token_bytes(32))
        return {"generated": True}
    if args.vault is None:
        raise UsageError("Kasa konumunu --vault ile açıkça belirtin.")
    if args.keyfile and within(no_links(args.keyfile), no_links(args.vault)):
        raise UsageError("Anahtar dosyası kasanın dışında olmalı.")
    key = read_keyfile(args.keyfile) if args.keyfile else None
    if args.command == "init":
        password = _password(data, new=True)
        recovery, confirmation = _new_recovery(args.recovery_out, args.vault, data)
        Vault.create(args.vault, password, recovery, confirmation, key)
        return {"created": True, "release": "beta", "recovery_confirmed": True}
    if args.command == "recover":
        recovery = (
            read_recovery(args.recovery_in)
            if args.recovery_in
            else _hex_key(data.get("recovery_key", ""))
        )
        with Vault.open(args.vault, recovery=recovery) as vault:
            password = _password(data, "new_password", new=True)
            _confirm(
                args, "Kasa erişimi ve kurtarma anahtarı yenilenecek. Eski yedekler etkilenmez."
            )
            new_recovery, confirmation = _new_recovery(
                args.recovery_out, args.vault, data, rotate=True
            )
            new_key = read_keyfile(args.new_keyfile) if args.new_keyfile else None
            if args.new_keyfile and within(no_links(args.new_keyfile), vault.root):
                raise UsageError("Anahtar dosyası kasanın dışında olmalı.")
            return vault.change_access(password, new_key, new_recovery, confirmation)
    password = _password(data)
    with _progress(not args.json) as event:
        if args.command == "restore":
            _confirm(args, "Şifreli yedek yeni konuma geri yüklenecek ve doğrulanacak.")
            return Vault.restore(args.vault, args.destination, password, key, event=event)
        with Vault.open(args.vault, password, key) as vault:
            if args.command == "add":
                preview = vault.preview_add(args.paths)
                if args.dry_run:
                    return {
                        "files": sorted(preview["files"]),
                        "count": preview["count"],
                        "bytes": preview["bytes"],
                    }
                _confirm(
                    args,
                    f"{preview['count']} dosya, {preview['bytes']} bayt kasaya kopyalanacak; kaynaklar korunur.",
                )
                return vault.add(args.paths, event)
            if args.command == "list":
                return vault.list()
            if args.command == "export":
                _confirm(
                    args, "Seçili kayıtlar doğrulanıp açık dosyalar olarak dışarı aktarılacak."
                )
                return vault.export(args.destination, args.names or None, event)
            if args.command == "remove":
                _confirm(
                    args,
                    "Seçili kayıtlar kasadan silinecek; kaynaklar ve eski yedekler etkilenmez.",
                )
                return vault.remove(args.names)
            if args.command == "verify":
                return vault.verify(event)
            if args.command == "backup":
                return vault.backup(args.destination, event)
            if args.command == "passwd":
                new_password = _password(data, "new_password", new=True)
                return vault.change_access(new_password, key)
            if args.command == "keyfile":
                _confirm(
                    args, "Kasanın anahtar dosyası gereksinimi değişecek. Eski yedekler etkilenmez."
                )
                if args.action == "enable":
                    if args.new_keyfile is None:
                        raise UsageError(
                            "Anahtar dosyası etkinleştirmek için --new-keyfile gerekli."
                        )
                    if within(no_links(args.new_keyfile), vault.root):
                        raise UsageError("Anahtar dosyası kasanın dışında olmalı.")
                    new_key = read_keyfile(args.new_keyfile)
                else:
                    new_key = None
                return vault.change_access(password, new_key)
            if args.command == "migrate":
                _confirm(args, "Eski dosyalar okunarak yeni kasaya taşınacak; orijinaller korunur.")
                legacy_key = read_bounded(args.legacy_key, 64).strip()
                return vault.import_legacy(args.paths, legacy_key, event)
            if args.command == "doctor":
                return vault.doctor()
    raise UsageError("Bilinmeyen komut.")


def display(result: dict) -> None:
    if "files" in result and isinstance(result["files"], list):
        table = Table(box=None, padding=(0, 2))
        table.add_column("Dosya", style="cyan", no_wrap=False)
        table.add_column("Bayt", justify="right")
        for entry in result["files"]:
            if isinstance(entry, dict):
                table.add_row(entry["name"], str(entry["size"]))
            else:
                table.add_row(entry, "")
        console.print(table)
        if not result["files"]:
            console.print("Kasa henüz dosya içermiyor.")
        if result.get("directories"):
            console.print("Klasörler: " + ", ".join(result["directories"]))
    elif "status" in result:
        console.print("Güvenlik Durumu", style="bold cyan")
        console.print("Sürüm: beta · bağımsız güvenlik incelemesi henüz tamamlanmadı")
        console.print("Şifreleme: " + result["cipher"])
        console.print("Parola türetme: Argon2id · 256 MiB · 3 geçiş")
        console.print(
            "Anahtar dosyası: " + ("gerekli" if result["keyfile_required"] else "etkin değil")
        )
        console.print("Kurtarma doğrulaması (UTC): " + result["status"]["recovery_confirmed_at"])
        for label, field in (
            ("Tam bütünlük kontrolü", "verified"),
            ("Doğrulanmış yedek", "backup"),
        ):
            record = result["status"][field]
            if record is None:
                console.print(label + ": henüz yapılmadı")
            else:
                coverage = (
                    "mevcut kayıtları kapsıyor"
                    if record["covers_current_catalog"]
                    else "kayıtlar sonradan değişti"
                )
                console.print(f"{label} (UTC): {record['at']} · {coverage}")
        if result["inactive_generations"]:
            console.print(
                "Tamamlanmamış nesil temizliği var; başarılı bir kasa işlemi sonrası tekrar kontrol edin.",
                style="yellow",
            )
        if result["missing_objects"]:
            console.print("Eksik şifreli nesne var; sağlam yedeği kontrol edin.", style="red")
        if result["unreferenced_ciphertext_files"]:
            console.print("Tamamlanmamış işlemlerden kalan şifreli nesneler var.", style="yellow")
    else:
        console.print("İşlem tamamlandı.", style="green")
        for key, value in result.items():
            console.print(f"{key}: {value}")


def timed_input(prompt: str, timeout: float = IDLE_SECONDS, hidden: bool = False) -> str:
    """No input threads: timeout returns with no thread retaining vault secrets."""
    sys.stdout.write(prompt)
    sys.stdout.flush()
    if os.name == "nt":
        import msvcrt

        deadline = time.monotonic() + timeout
        chars = []
        while time.monotonic() < deadline:
            if not msvcrt.kbhit():
                time.sleep(0.05)
                continue
            char = msvcrt.getwch()
            deadline = time.monotonic() + timeout
            if char in ("\x00", "\xe0"):
                msvcrt.getwch()
                continue
            if char == "\x03":
                raise KeyboardInterrupt()
            if char in ("\r", "\n"):
                sys.stdout.write("\n")
                try:
                    return "".join(chars).encode("utf-16-le", "surrogatepass").decode("utf-16-le")
                except UnicodeError as exc:
                    raise UsageError("Giriş geçerli Unicode değil.") from exc
            if char == "\x08":
                if chars:
                    chars.pop()
                    if not hidden:
                        sys.stdout.write("\b \b")
            elif char >= " " and len(chars) < 4096:
                chars.append(char)
                if not hidden:
                    sys.stdout.write(char)
            sys.stdout.flush()
        raise SessionTimeout()
    import select
    import termios

    old = termios.tcgetattr(sys.stdin.fileno()) if hidden else None
    try:
        if old is not None:
            changed = old.copy()
            changed[3] &= ~termios.ECHO
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, changed)
        if not select.select([sys.stdin], [], [], timeout)[0]:
            raise SessionTimeout()
        line = sys.stdin.readline()
        if not line:
            raise EOFError()
        return line.rstrip("\r\n")
    finally:
        if old is not None:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
            sys.stdout.write("\n")


def _menu_path(label: str) -> Path:
    value = timed_input(label + ": ").strip().strip('"')
    if not value:
        raise UsageError("Konum boş olamaz.")
    return Path(value)


def _menu_new_password() -> str:
    value = timed_input("Yeni parola: ", hidden=True)
    confirmation = timed_input("Parolayı tekrarla: ", hidden=True)
    if not hmac.compare_digest(value.encode(), confirmation.encode()):
        raise UsageError("Parolalar eşleşmiyor.")
    crypto.validate_password(value)
    return value


def _menu_recovery(root: Path) -> tuple[bytes, bytes]:
    path = _menu_path("Yeni kurtarma dosyasının ayrı konumu")
    path = _outside_secret(path, root)
    key = secrets.token_bytes(32)
    write_private(path, RECOVERY_PREFIX + key.hex().encode("ascii") + b"\n")
    console.print("Dosya kaydedildi. Kurtarma anahtarı tek başına erişim sağlar; ayrı saklayın.")
    confirmed = _hex_key(
        timed_input("Dosyadaki 64 karakterlik anahtarı tekrar girin: ", hidden=True)
    )
    if not hmac.compare_digest(key, confirmed):
        raise UsageError("Kurtarma doğrulanamadı; kasa değişmedi.")
    return key, confirmed


def menu(initial: Path | None = None) -> int:
    if not sys.stdin.isatty():
        raise UsageError("Menü için etkileşimli terminal gerekli; komut kullanın (--help).")
    vault = None
    preferred = initial
    try:
        while True:
            try:
                console.print("\nPSYPHER", style="bold cyan")
                console.print("Yerel dosya kasası · 2.0 beta", style="dim")
                if vault is None:
                    console.print(
                        "1  Kasayı aç       2  Yeni kasa       3  Kurtarma\n4  Yedeği geri yükle       0  Çıkış"
                    )
                    choice = timed_input("Seçim: ").strip()
                    if choice == "0":
                        return 0
                    if choice == "2":
                        root = _menu_path("Yeni kasa konumu")
                        password = _menu_new_password()
                        key = None
                        if timed_input("Anahtar dosyası da kullanılsın mı? (e/H): ").lower() == "e":
                            key_path = _outside_secret(
                                _menu_path("Yeni anahtar dosyası konumu"), root
                            )
                            key = secrets.token_bytes(32)
                            write_private(key_path, key)
                        recovery, confirmation = _menu_recovery(root)
                        Vault.create(root, password, recovery, confirmation, key)
                        preferred = root
                        del password, recovery, confirmation, key
                        console.print(
                            "Kasa oluşturuldu. Kaynak dosyalar kendiliğinden taranmaz.",
                            style="green",
                        )
                        continue
                    if choice not in {"1", "3", "4"}:
                        raise UsageError("Geçerli bir seçim yapın.")
                    root = (
                        preferred
                        if choice == "1" and preferred
                        else _menu_path("Kasa/yedek konumu")
                    )
                    key = None
                    if choice == "3":
                        recovery = read_recovery(_menu_path("Mevcut kurtarma dosyası"))
                        with Vault.open(root, recovery=recovery) as recovering:
                            new_password = _menu_new_password()
                            new_recovery, confirmation = _menu_recovery(root)
                            recovering.change_access(
                                new_password, recovery=new_recovery, confirmation=confirmation
                            )
                        del recovery, new_password, new_recovery, confirmation
                        console.print(
                            "Erişim yenilendi. Yeni parolayla kasayı açın.", style="green"
                        )
                        continue
                    if timed_input("Anahtar dosyası gerekli mi? (e/H): ").lower() == "e":
                        key = read_keyfile(_menu_path("Anahtar dosyası konumu"))
                    password = timed_input("Kasa parolası: ", hidden=True)
                    if choice == "4":
                        destination = _menu_path("Yeni geri yükleme konumu")
                        with _progress(True) as event:
                            display(Vault.restore(root, destination, password, key, event=event))
                        del password, key
                        continue
                    vault = Vault.open(root, password, key)
                    preferred = root
                    del password, key
                console.print(f"{len(vault.catalog['files'])} dosya · kasa açık", style="dim")
                console.print(
                    "1  Listele       2  Dosya/klasör ekle       3  Dışarı aktar\n"
                    "4  Bütünlüğü doğrula       5  Şifreli yedek       6  Güvenlik durumu\n"
                    "7  Parolayı değiştir       8  Kaydı sil       9  Anahtar dosyası\n"
                    "10 Eski dosya taşı       K  Kilitle       0  Çıkış"
                )
                choice = timed_input("Seçim: ").strip().lower()
                if choice in {"0", "k"}:
                    vault.close()
                    vault = None
                    console.clear()
                    if choice == "0":
                        return 0
                    continue
                with _progress(True) as event:
                    if choice == "1":
                        display(vault.list())
                    elif choice == "2":
                        source = _menu_path("Kaynak dosya veya klasör")
                        preview = vault.preview_add([source])
                        console.print(
                            f"{preview['count']} dosya · {preview['bytes']} bayt. Kaynaklar korunur."
                        )
                        if timed_input("Kopyalamak için EVET yazın: ") == "EVET":
                            display(vault.add([source], event))
                    elif choice == "3":
                        name = timed_input("Kasa yolu (hepsi için boş bırak): ").strip()
                        destination = _menu_path("Açık dosyaların hedef klasörü")
                        console.print("Çıkarılan dosyalar artık şifreli değildir.")
                        if timed_input("Dışarı aktarmak için EVET yazın: ") == "EVET":
                            display(vault.export(destination, [name] if name else None, event))
                    elif choice == "4":
                        display(vault.verify(event))
                    elif choice == "5":
                        display(vault.backup(_menu_path("Yeni şifreli yedek klasörü"), event))
                    elif choice == "6":
                        display(vault.doctor())
                    elif choice == "7":
                        key = (
                            read_keyfile(_menu_path("Mevcut anahtar dosyası"))
                            if vault.header["password"]["keyfile"]
                            else None
                        )
                        password = _menu_new_password()
                        display(vault.change_access(password, key))
                        del password, key
                    elif choice == "8":
                        name = timed_input("Silinecek kasa yolu: ")
                        if timed_input("Kasadan silmek için EVET yazın: ") == "EVET":
                            display(vault.remove([name]))
                    elif choice == "9":
                        password = timed_input("Mevcut kasa parolası: ", hidden=True)
                        current_key = (
                            read_keyfile(_menu_path("Mevcut anahtar dosyası"))
                            if vault.header["password"]["keyfile"]
                            else None
                        )
                        crypto.unlock(vault.header, password, current_key)
                        key = None
                        if (
                            timed_input("Yeni anahtar dosyası etkinleştirilsin mi? (e/H): ").lower()
                            == "e"
                        ):
                            path = _outside_secret(
                                _menu_path("Yeni anahtar dosyası konumu"), vault.root
                            )
                            key = secrets.token_bytes(32)
                            write_private(path, key)
                        display(vault.change_access(password, key))
                        del password, current_key, key
                    elif choice == "10":
                        source = _menu_path("Eski _psykhenc dosyası")
                        old_key = read_bounded(
                            _menu_path("Eski Fernet anahtar dosyası"), 64
                        ).strip()
                        display(vault.import_legacy([source], old_key, event))
                        del old_key
                    else:
                        raise UsageError("Geçerli bir seçim yapın.")
            except SessionTimeout:
                if vault is not None:
                    vault.close()
                    vault = None
                console.clear()
                console.print("5 dakika işlem yapılmadığı için oturum kilitlendi.", style="yellow")
            except PsypherError as exc:
                if isinstance(exc, IntegrityError) or exc.code == 5:
                    if vault is not None:
                        vault.close()
                        vault = None
                error_console.print(str(exc), style="red")
            except OSError:
                if vault is not None:
                    vault.close()
                    vault = None
                error_console.print(
                    "Dosya işlemi tamamlanamadı. Konumu, izinleri ve boş alanı kontrol edin.",
                    style="red",
                )
            finally:
                # Also clear secrets when validation, cancellation, or timeout interrupted a prompt.
                password = key = current_key = recovery = confirmation = None
                new_password = new_recovery = old_key = None
    finally:
        if vault is not None:
            vault.close()


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    json_mode = "--json" in arguments
    # Stable UTF-8 for Windows pipes; console rendering remains Rich's responsibility.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        args = parser().parse_args(arguments)
        if args.command is None:
            if args.json or args.secrets_fd is not None:
                raise UsageError("JSON/otomasyon kullanımında bir komut gerekli.")
            return menu(args.vault)
        data = _read_secrets(args.secrets_fd)
        try:
            result = execute(args, data)
        finally:
            data.clear()
        if args.json:
            print(json.dumps({"ok": True, "result": result}, ensure_ascii=True))
        else:
            display(result)
        return 0
    except (KeyboardInterrupt, SessionTimeout):
        code, message = 130, "İşlem iptal edildi; tamamlanmamış kayıtlar yayımlanmadı."
    except EOFError:
        code, message = 2, "Giriş sona erdi; işlem tamamlanmadı."
    except PsypherError as exc:
        code, message = exc.code, str(exc)
    except OSError:
        code, message = 5, "Dosya işlemi tamamlanamadı. Konumu, izinleri ve boş alanı kontrol edin."
    if json_mode:
        print(
            json.dumps(
                {"ok": False, "error": {"code": code, "message": message}}, ensure_ascii=True
            )
        )
    else:
        error_console.print(message, style="red")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
