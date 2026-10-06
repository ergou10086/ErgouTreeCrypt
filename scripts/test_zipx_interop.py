#!/usr/bin/env python3
"""Reproduce the real-file JVM/Android ART ZIPX four-direction matrix.

Usage: python scripts/test_zipx_interop.py --adb PATH [--serial DEVICE]
       [--sevenzip PATH] [--source FILE] [--skip-generate] [--skip-build] [--refresh-raw]
Transfers only task-owned artifacts via the debug app's private storage, without root.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "hbnu.project.ergoutreecrypt.debug"
OUTPUT = ROOT / "target/zipx-interop"


def run(args, cwd=ROOT):
    """Run a checked argument-vector command."""
    subprocess.run([str(arg) for arg in args], cwd=cwd, check=True)


def transfer_to_app(adb, source):
    """Stream a complete corpus into the task-owned debug application directory."""
    run(adb + ["shell", "run-as", PACKAGE, "mkdir", "-p", "files/zipx-interop/desktop"])
    process = subprocess.Popen(adb + ["exec-in", "run-as", PACKAGE, "tar", "-xf", "-", "-C", "files/zipx-interop/desktop"], stdin=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
            for path in sorted(source.iterdir()):
                archive.add(path, arcname=path.name)
    except BaseException:
        process.terminate()
        process.wait()
        raise
    finally:
        process.stdin.close()
    if process.wait() != 0:
        raise RuntimeError("ZIPX corpus transfer to ART failed")


def transfer_from_app(adb, output):
    """Retrieve artifacts without accepting symlinks or paths outside the output directory."""
    output.mkdir(parents=True, exist_ok=True)
    exported = "files/zipx-interop/android-export.tar"
    run(adb + ["shell", "run-as", PACKAGE, "tar", "-cf", exported, "-C", "files/zipx-interop/android", "."])
    expected = subprocess.check_output(adb + ["shell", "run-as", PACKAGE, "sha256sum", exported], text=True).split()[0]
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix="android-transfer-", suffix=".tar", delete=False) as received:
        transfer = Path(received.name)
        subprocess.run(adb + ["exec-out", "run-as", PACKAGE, "cat", exported],
                       stdout=received, check=True)
    with transfer.open("rb") as received:
        if hashlib.file_digest(received, "sha256").hexdigest() != expected:
            raise RuntimeError("ADB corpus transport SHA-256 mismatch; diagnostic transfer retained: " + str(transfer))
    with tarfile.open(transfer, mode="r:") as archive:
        for entry in archive:
            target = (output / entry.name).resolve()
            if not target.is_relative_to(output.resolve()):
                raise RuntimeError("Unsafe ZIPX artifact path")
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif entry.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(entry) as source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
            else:
                raise RuntimeError("Unsupported ZIPX artifact entry")
    transfer.unlink()
    run(adb + ["shell", "run-as", PACKAGE, "rm", exported])


def external_verification(sevenzip, corpus):
    """Use an external decoder to verify produced codecs and standard AES envelopes."""
    archives = sorted(corpus.glob("archive-*.zipx"))
    if len(archives) != 6:
        raise RuntimeError("Expected all six plain/AES production archives: " + str(corpus))
    for path in archives:
        output = OUTPUT / "external" / corpus.name / path.stem
        password = "zipx-归档🔐" if path.stem.endswith("true") else ""
        password = sevenzip_password_bytes(password)
        run([sevenzip, "t", "-y", "-sccUTF-8", "-p" + password, path])
        run([sevenzip, "x", "-y", "-sccUTF-8", "-p" + password, "-o" + str(output), path])
        source = output / "目录/[ひなみ桜花][2024-01-25].m4a"
        with source.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        with (corpus / "source.m4a").open("rb") as stream:
            expected = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != expected or not (output / "empty").is_file() or (output / "empty").stat().st_size:
            raise RuntimeError("External ZIPX restoration mismatch: " + str(path))
        shutil.rmtree(output)


def sevenzip_password_bytes(password):
    """Preserve UTF-8 password bytes through Windows 7-Zip's documented CP_ACP conversion.

    This is a test adapter, not a claim that typing the same Unicode text in the
    Windows 7-Zip UI is interoperable. Production passwords remain UTF-8 on both
    runtimes. Fail rather than replace any bytes that the active code page cannot
    represent. ASCII passwords need no adaptation.
    """
    if os.name != "nt" or password.isascii():
        return password
    import ctypes
    codepage = ctypes.windll.kernel32.GetACP()
    encoding = "utf-8" if codepage == 65001 else "cp" + str(codepage)
    encoded = password.encode("utf-8")
    try:
        adapted = encoded.decode(encoding)
        if adapted.encode(encoding) != encoded:
            raise ValueError("Password bytes did not roundtrip")
        return adapted
    except (UnicodeError, ValueError) as error:
        raise RuntimeError("Windows 7-Zip cannot represent these UTF-8 password bytes with code page "
                           + str(codepage) + "; use an external decoder with UTF-8 password support") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=shutil.which("adb"))
    parser.add_argument("--serial")
    parser.add_argument("--source", type=Path, default=ROOT / "src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a")
    parser.add_argument("--sevenzip", type=Path)
    parser.add_argument("--skip-generate", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--refresh-raw", action="store_true",
                        help="Revalidate raw codec cases after a successful full matrix; retain unchanged volume cases")
    args = parser.parse_args()
    if not args.adb or not args.source.is_file():
        parser.error("An adb executable and an existing real source file are required")
    adb = [args.adb] + (["-s", args.serial] if args.serial else [])
    maven = shutil.which("mvn")
    if not maven:
        parser.error("Maven must be on PATH")
    started = time.time()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if args.refresh_raw:
        full_log = OUTPUT / "android-instrumentation.log"
        desktop_result = ROOT / "target/surefire-reports/TEST-hbnu.project.ergoutreecrypt.fileops.ZipxInteropTest.xml"
        if not full_log.is_file() or "OK (4 tests)" not in full_log.read_text(encoding="utf-8"):
            parser.error("Raw revalidation requires a completed full ART matrix")
        suite = ET.parse(desktop_result).getroot()
        if suite.get("failures") != "0" or suite.get("errors") != "0" or suite.get("skipped") != "0" or not any(
                case.get("name") == "readAndroidCorpus" for case in suite.findall("testcase")):
            parser.error("Raw revalidation requires successful Android-to-desktop full-corpus verification")
        (OUTPUT / "full-desktop-reader.xml").write_bytes(desktop_result.read_bytes())
    if args.sevenzip:
        run([maven, "-q", "-Dtest=ZipxExternalDecoderTest", "-Dzipx.external.7zip=" + str(args.sevenzip.resolve()), "test"])
    if not args.skip_generate:
        if args.refresh_raw:
            run([maven, "-q", "-Dtest=ZipxArchiveTest,ZipxInteropTest#refreshDesktopRawArchives", "-Dzipx.interop.refresh=true", "test"])
        else:
            run([maven, "-q", "-Dtest=ZipxArchiveTest,NativeArchivePasswordTest,EncryptArchiveStagingTest,ArchiveProgressPhaseTest,CompressBeforeEncryptTest,DecryptThenExtractTest", "test"])
            run([maven, "-q", "-Dtest=ZipxInteropTest#generateDesktopCorpus", "-Dzipx.interop.generate=true", "-Dzipx.real.file=" + str(args.source.resolve()), "test"])
    if not args.skip_build:
        wrapper = ROOT / "android" / ("gradlew.bat" if os.name == "nt" else "gradlew")
        run([wrapper, ":app:assembleDebug", ":app:assembleDebugAndroidTest", ":shared-test:test", "--tests", "*ZipxArchiveTest", "--console=plain"], ROOT / "android")
    run(adb + ["install", "-r", ROOT / "android/app/build/outputs/apk/debug/app-debug.apk"])
    run(adb + ["install", "-r", ROOT / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"])
    transfer_to_app(adb, OUTPUT / "desktop")
    classes = "hbnu.project.ergoutreecrypt.android.ZipxArchiveUiTest,hbnu.project.ergoutreecrypt.android.ZipxMediaArchiveTest,"
    classes += ("hbnu.project.ergoutreecrypt.android.ZipxRawInteropTest,hbnu.project.ergoutreecrypt.android.ZipxInteropTest#independentFixturesAndFailuresOnArt"
                if args.refresh_raw else "hbnu.project.ergoutreecrypt.android.ZipxInteropTest")
    result = subprocess.run(adb + ["shell", "am", "instrument", "-w", "-e", "class", classes,
                                  PACKAGE + ".test/androidx.test.runner.AndroidJUnitRunner"], capture_output=True, text=True)
    log_name = "android-raw-instrumentation.log" if args.refresh_raw else "android-instrumentation.log"
    (OUTPUT / log_name).write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout, flush=True)
    if result.returncode or "FAILURES!!!" in result.stdout or "OK (4 tests)" not in result.stdout:
        raise RuntimeError("ART instrumentation failed; inspect " + str(OUTPUT / log_name))
    transfer_from_app(adb, OUTPUT / "android")
    reader = "readAndroidRawArchives" if args.refresh_raw else "readAndroidCorpus"
    run([maven, "-q", "-Dtest=ZipxInteropTest#" + reader, "-Dzipx.interop.android=" + str(OUTPUT / "android"), "test"])
    if args.sevenzip:
        external_verification(args.sevenzip.resolve(), OUTPUT / "desktop")
        external_verification(args.sevenzip.resolve(), OUTPUT / "android")
    with args.source.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    for corpus in (OUTPUT / "desktop", OUTPUT / "android"):
        manifest = (corpus / "manifest.properties").read_text(encoding="iso-8859-1")
        declared = next(line.partition("=")[2] for line in manifest.splitlines() if line.startswith("source.sha256="))
        if declared != digest:
            raise RuntimeError("Corpus was generated from a different real source file: " + str(corpus))
    device = subprocess.check_output(adb + ["shell", "getprop", "ro.build.version.sdk"], text=True).strip()
    report = {"source": str(args.source.resolve()), "bytes": args.source.stat().st_size, "sha256": digest,
              "android_api": device, "cases_per_direction": 14, "directions": ["desktop-desktop", "desktop-android", "android-android", "android-desktop"],
              "checks_per_case": ["authentication", "extraction/decryption and SHA-256"], "golden_fixtures": 23,
              "external_decoder": str(args.sevenzip) if args.sevenzip else None,
              "external_ascii_password_verified": bool(args.sevenzip),
              "external_password_encoding": "UTF-8 bytes; Windows 7-Zip CLI uses an explicit CP_ACP byte adapter",
              "raw_revalidation_checks": 48 if args.refresh_raw else 0,
              "full_matrix_evidence": "android-instrumentation.log and full-desktop-reader.xml" if args.refresh_raw else "current run",
              "elapsed_seconds": round(time.time() - started)}
    (OUTPUT / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("ZIPX: 4 directions x 14 cases x 2 independent checks = 112 checks passed. SHA-256:", digest)
    if args.refresh_raw:
        print("Also passed 4 directions x 6 raw cases x 2 checks = 48 targeted checks after the empty-XZ fix.")


if __name__ == "__main__":
    main()
