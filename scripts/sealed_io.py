"""Authenticated encrypted inputs and artifacts. Never print a key or plaintext."""
import base64
import os
from pathlib import Path, PurePosixPath
import stat
import zipfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'BEFOREEMPTY-AES256GCM-V1\n'

def key_from_env():
    key = base64.b64decode(os.environ['BUILD_INPUT_KEY'], validate=True)
    if len(key) != 32:
        raise ValueError('A 256-bit key is required.')
    return key

def seal(data, key):
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)

def unseal(data, key):
    if not data.startswith(MAGIC) or len(data) < len(MAGIC)+28:
        raise ValueError('Unsupported sealed bundle.')
    body = data[len(MAGIC):]
    return AESGCM(key).decrypt(body[:12], body[12:], MAGIC)

def extract_zip(data, destination):
    import io
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [e.filename for e in entries]
        if len(names) != len(set(names)) or sum(e.file_size for e in entries) > 1024**3:
            raise ValueError('Duplicate or oversized archive.')
        checked=[]
        for entry in entries:
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            raw = entry.orig_filename
            if (not path.parts or path.is_absolute() or '..' in path.parts
                    or '\\' in raw or ':' in raw
                    or stat.S_ISLNK(mode) or entry.flag_bits & 1):
                raise ValueError('Unsafe archive entry.')
            target = root.joinpath(*path.parts).resolve()
            if not target.is_relative_to(root):
                raise ValueError('Archive escapes the private workspace.')
            checked.append((entry,target,mode))
        for entry,target,mode in checked:
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(entry))
                target.chmod(0o700 if mode & 0o111 else 0o600)
