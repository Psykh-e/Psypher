import copy
import io
import secrets
import struct

import pytest
from nacl import bindings as sodium

from psypher import crypto
from psypher.errors import AccessError, IntegrityError, UsageError


def encrypt(data, key, context=b"test-context"):
    output = io.BytesIO()
    crypto.encrypt_stream(io.BytesIO(data), output, key, context)
    return output.getvalue()


def decrypt(data, key, context=b"test-context"):
    output = io.BytesIO()
    crypto.decrypt_stream(io.BytesIO(data), output, key, context)
    return output.getvalue()


@pytest.mark.parametrize(
    "size",
    [
        0,
        1,
        31,
        crypto.CHUNK_SIZE - 1,
        crypto.CHUNK_SIZE,
        crypto.CHUNK_SIZE + 1,
        3 * crypto.CHUNK_SIZE + 23,
    ],
)
def test_stream_roundtrip(size):
    data = secrets.token_bytes(size)
    key = secrets.token_bytes(32)
    first = encrypt(data, key)
    assert first != encrypt(data, key)
    assert decrypt(first, key) == data


def frames(ciphertext):
    header = ciphertext[:32]
    result = []
    cursor = 32
    while cursor < len(ciphertext):
        size = struct.unpack(">I", ciphertext[cursor : cursor + 4])[0]
        result.append(ciphertext[cursor : cursor + 4 + size])
        cursor += 4 + size
    return header, result


@pytest.fixture
def encrypted():
    key = secrets.token_bytes(32)
    return key, encrypt(b"x" * (crypto.CHUNK_SIZE * 2 + 3), key)


@pytest.mark.parametrize("position", [0, 8, 31, 32, 36, 100, -1])
def test_mutation(encrypted, position):
    key, value = encrypted
    damaged = bytearray(value)
    damaged[position] ^= 1
    with pytest.raises(IntegrityError):
        decrypt(damaged, key)


@pytest.mark.parametrize("cut", [0, 1, 8, 31, 32, 33, 36, 70, -1, -20, -21])
def test_truncation(encrypted, cut):
    key, value = encrypted
    with pytest.raises(IntegrityError):
        decrypt(value[:cut], key)


@pytest.mark.parametrize("attack", ["reorder", "duplicate", "remove", "remove-final", "append"])
def test_frame_attacks(encrypted, attack):
    key, value = encrypted
    prefix, items = frames(value)
    if attack == "reorder":
        items[0], items[1] = items[1], items[0]
    elif attack == "duplicate":
        items.insert(1, items[0])
    elif attack == "remove":
        items.pop(1)
    elif attack == "remove-final":
        items.pop()
    else:
        items.append(b"extra")
    with pytest.raises(IntegrityError):
        decrypt(prefix + b"".join(items), key)


def test_object_context_and_key_binding():
    key = secrets.token_bytes(32)
    encrypted = encrypt(b"example", key, b"vault-a/object-a")
    for other_key, other_context in (
        (key, b"vault-b/object-a"),
        (key, b"vault-a/object-b"),
        (secrets.token_bytes(32), b"vault-a/object-a"),
    ):
        with pytest.raises(IntegrityError):
            decrypt(encrypted, other_key, other_context)


@pytest.mark.parametrize(
    "tag,plain",
    [
        (sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL, b"data"),
        (sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE, b""),
        (sodium.crypto_secretstream_xchacha20poly1305_TAG_PUSH, b"data"),
    ],
)
def test_noncanonical_stream_tags(tag, plain):
    key = secrets.token_bytes(32)
    state = sodium.crypto_secretstream_xchacha20poly1305_state()
    prefix = crypto.MAGIC + sodium.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    size = len(plain) + 17
    message = sodium.crypto_secretstream_xchacha20poly1305_push(
        state, plain, b"test-context" + struct.pack(">QI", 0, size), tag
    )
    with pytest.raises(IntegrityError):
        decrypt(prefix + struct.pack(">I", size) + message, key)


def test_expected_size_is_enforced():
    key = secrets.token_bytes(32)
    value = encrypt(b"12345", key)
    for size in (4, 6):
        with pytest.raises(IntegrityError):
            crypto.decrypt_stream(io.BytesIO(value), None, key, b"test-context", expected_size=size)


def test_short_reads():
    class ShortReads(io.BytesIO):
        def read(self, size=-1):
            return super().read(min(size, 7))

    key = secrets.token_bytes(32)
    plain = b"hello" * 100
    output = io.BytesIO()
    crypto.decrypt_stream(ShortReads(encrypt(plain, key)), output, key, b"test-context")
    assert output.getvalue() == plain


def test_password_keyfile_and_independent_recovery():
    recovery, keyfile = secrets.token_bytes(32), secrets.token_bytes(32)
    password = "a-long-test-passphrase"
    header, master = crypto.create_header(password, recovery, keyfile)
    assert crypto.unlock(header, password, keyfile) == master
    assert crypto.unlock(header, recovery=recovery) == master
    for guess, factor in (
        ("wrong", keyfile),
        (password, secrets.token_bytes(32)),
        (password, None),
    ):
        with pytest.raises(AccessError):
            crypto.unlock(header, guess, factor)
    with pytest.raises(AccessError):
        crypto.unlock(header, recovery=secrets.token_bytes(32))
    assert crypto.derive(master, header["vault_id"], "catalog/x") != crypto.derive(
        master, header["vault_id"], "object/x"
    )


@pytest.mark.parametrize("change", ["memory", "passes", "type", "version", "extra", "nonce"])
def test_header_bounds_before_kdf(change, monkeypatch):
    header, _ = crypto.create_header("long-test-passphrase", secrets.token_bytes(32))
    if change == "memory":
        header["password"]["memlimit"] = 2**63
    elif change == "passes":
        header["password"]["opslimit"] = 10**20
    elif change == "type":
        header["password"]["keyfile"] = 0
    elif change == "version":
        header["version"] = 99
    elif change == "extra":
        header["surprise"] = 1
    else:
        header["password"]["nonce"] = "!"

    def forbidden(*args, **kwargs):
        pytest.fail("Untrusted header reached KDF")

    monkeypatch.setattr(crypto.argon2id, "kdf", forbidden)
    with pytest.raises(IntegrityError):
        crypto.unlock(header, "long-test-passphrase")


def test_wrap_aad_binds_access_method():
    recovery = secrets.token_bytes(32)
    header, _ = crypto.create_header("long-test-passphrase", recovery)
    tampered = copy.deepcopy(header)
    tampered["vault_id"] = crypto.new_id()
    with pytest.raises(AccessError):
        crypto.unlock(tampered, recovery=recovery)


@pytest.mark.parametrize("value", [b'{"x":1,"x":2}', b'{"x":NaN}', b"[]", b"{", b"\xff"])
def test_strict_json(value):
    with pytest.raises(IntegrityError):
        crypto.parse_json(value, 100)


def test_no_silent_kdf_downgrade(monkeypatch):
    def exhausted(*args, **kwargs):
        assert kwargs["memlimit"] == 256 * 1024 * 1024
        assert kwargs["opslimit"] == 3
        raise MemoryError()

    monkeypatch.setattr(crypto.argon2id, "kdf", exhausted)
    with pytest.raises(AccessError):
        crypto.create_header("long-test-passphrase", secrets.token_bytes(32))


@pytest.mark.parametrize("password", ["", "test", "x" * 1025])
def test_new_password_policy(password):
    with pytest.raises(UsageError):
        crypto.create_header(password, secrets.token_bytes(32))


def test_invalid_password_unicode_is_rejected():
    with pytest.raises(UsageError):
        crypto.validate_password("x" * 12 + "\ud800")
