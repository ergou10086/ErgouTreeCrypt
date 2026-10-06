#!/usr/bin/env python3
"""Generate independent small ZIPX fixtures with Python codecs and optional 7-Zip.

Usage: python scripts/generate_zipx_fixtures.py [--sevenzip PATH]
The golden files contain synthetic text only. The production Java writer is never used.
"""
import argparse
import binascii
import hashlib
import io
import lzma
from pathlib import Path
import struct
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "src/test/resources/zipx/golden"
PAYLOAD = b"Independent ZIPX reference\n" * 32


class NonSeekable(io.BytesIO):
    """Force Python's ZIP data-descriptor path."""
    def seekable(self):
        return False

    def seek(self, *args):
        raise io.UnsupportedOperation("non-seekable reference stream")


def raw_zip(name, method, data, extra=b"", flags=0, crc=None):
    """Serialize ZIP records independently of Commons Compress and the Java writer."""
    filename = b"payload.txt"
    crc = binascii.crc32(PAYLOAD) if crc is None else crc
    local = struct.pack("<I5H3I2H", 0x04034b50, 63, flags, method, 0, 0x21,
                        crc, len(data), len(PAYLOAD), len(filename), len(extra))
    central = struct.pack("<I6H3I5H2I", 0x02014b50, 63, 63, flags, method, 0, 0x21,
                          crc, len(data), len(PAYLOAD), len(filename), len(extra), 0, 0, 0, 0, 0)
    body = local + filename + extra + data
    directory = central + filename + extra
    end = struct.pack("<I4H2IH", 0x06054b50, 0, 0, 1, 1, len(directory), len(body), 0)
    (GOLDEN / name).write_bytes(body + directory + end)


def aes_fixtures():
    """Use independent PBKDF2, AES-ECB counter blocks and HMAC for AE-1 and AE-2."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import hmac
    compressed = lzma.compress(PAYLOAD, format=lzma.FORMAT_XZ, preset=3)
    for version in (1, 2):
        for strength, keylen in ((1, 16), (2, 24), (3, 32)):
            salt = bytes(range(keylen // 2))
            key = hashlib.pbkdf2_hmac("sha1", b"reference-password", salt, 1000, keylen * 2 + 2)
            encryptor = Cipher(algorithms.AES(key[:keylen]), modes.ECB()).encryptor()
            encrypted = bytearray()
            for offset in range(0, len(compressed), 16):
                mask = encryptor.update((offset // 16 + 1).to_bytes(16, "little"))
                encrypted.extend(a ^ b for a, b in zip(compressed[offset:offset + 16], mask))
            encryptor.finalize()
            tag = hmac.new(key[keylen:keylen * 2], encrypted, "sha1").digest()[:10]
            data = salt + key[-2:] + encrypted + tag
            extra = struct.pack("<HHH2sBH", 0x9901, 7, version, b"AE", strength, 95)
            raw_zip(f"python-xz-aes{keylen * 8}-ae{version}.zipx", 99, data, extra, 1,
                    0 if version == 2 else binascii.crc32(PAYLOAD))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sevenzip", type=Path)
    args = parser.parse_args()
    GOLDEN.mkdir(parents=True, exist_ok=True)
    for label, method in (("store", zipfile.ZIP_STORED), ("deflate", zipfile.ZIP_DEFLATED),
                          ("bzip2", zipfile.ZIP_BZIP2), ("lzma", zipfile.ZIP_LZMA)):
        for descriptor in (False, True):
            stream = NonSeekable() if descriptor else io.BytesIO()
            with zipfile.ZipFile(stream, "w", compression=method) as archive:
                with archive.open("目录/payload.txt", "w", force_zip64=True) as entry:
                    entry.write(PAYLOAD)
                archive.writestr("empty", b"")
            (GOLDEN / f"python-{label}-{'descriptor' if descriptor else 'zip64'}.zipx").write_bytes(stream.getvalue())
    raw_zip("python-xz.zipx", 95, lzma.compress(PAYLOAD, format=lzma.FORMAT_XZ, preset=3))
    aes_fixtures()
    if args.sevenzip:
        work = ROOT / "target/zipx-reference"
        work.mkdir(parents=True, exist_ok=True)
        (work / "payload.txt").write_bytes(PAYLOAD)
        for label in ("Deflate64", "BZip2", "LZMA", "PPMd"):
            for aes in (False, True):
                filename = ("unsupported-" if label == "PPMd" else "") + f"7zip-{label.lower()}{'-aes' if aes else ''}.zipx"
                output = GOLDEN / filename
                if output.exists():
                    output.unlink()
                command = [str(args.sevenzip.resolve()), "a", "-tzip", f"-mm={label}", str(output), "payload.txt"]
                if aes:
                    command += ["-p" + "reference-password", "-mem=AES256"]
                subprocess.run(command, cwd=work, check=True, stdout=subprocess.DEVNULL)
    manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(GOLDEN.glob("*.zipx"))}
    (GOLDEN / "SHA256SUMS").write_text("".join(f"{value}  {name}\n" for name, value in manifest.items()), encoding="utf-8")
    print(f"Generated {len(manifest)} independent archives in {GOLDEN}")


if __name__ == "__main__":
    main()
