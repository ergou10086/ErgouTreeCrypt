#!/usr/bin/env python3
"""Reproduce the real-file JVM <-> Android ART LZ4 matrix using a debug APK.
No root is required: tar streams are transferred through adb run-as.
Usage: python scripts/test_lz4_interop.py --adb PATH [--serial DEVICE] [--source FILE]
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "hbnu.project.ergoutreecrypt.debug"

def run(args, cwd=ROOT):
    subprocess.run([str(a) for a in args], cwd=cwd, check=True)

def transfer_to_app(adb, source):
    run(adb + ["shell", "run-as", PACKAGE, "mkdir", "-p", "files/lz4-interop/desktop"])
    process = subprocess.Popen(adb + ["exec-in", "run-as", PACKAGE, "tar", "-xf", "-", "-C", "files/lz4-interop/desktop"], stdin=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdin, mode="w|") as archive:
            for path in sorted(source.iterdir()):
                if path.is_file():
                    archive.add(path, arcname=path.name)
    except BaseException:
        process.terminate()
        process.wait()
        raise
    finally:
        process.stdin.close()
    if process.wait() != 0:
        raise RuntimeError("Failed to transfer desktop corpus to the debug app")

def transfer_from_app(adb, output):
    output.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(adb + ["exec-out", "run-as", PACKAGE, "tar", "-cf", "-", "-C", "files/lz4-interop/android", "."], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for entry in archive:
                target = (output / entry.name).resolve()
                if not target.is_relative_to(output.resolve()):
                    raise RuntimeError("Unsafe artifact path")
                if entry.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif entry.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.extractfile(entry) as source, target.open("wb") as dest:
                        shutil.copyfileobj(source, dest)
                else:
                    raise RuntimeError("Unsupported artifact entry")
    except BaseException:
        process.terminate()
        process.wait()
        raise
    finally:
        process.stdout.close()
    if process.wait() != 0:
        raise RuntimeError("Failed to retrieve Android corpus")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=shutil.which("adb"), help="Android SDK adb executable")
    parser.add_argument("--serial", help="Device serial if more than one device is connected")
    parser.add_argument("--source", type=Path, default=ROOT / "src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a")
    args = parser.parse_args()
    if not args.adb or not args.source.is_file():
        parser.error("adb and an existing real source file are required")
    adb = [args.adb] + (["-s", args.serial] if args.serial else [])
    maven = shutil.which("mvn")
    if not maven:
        parser.error("Maven must be on PATH")
    run([maven, "-q", "-Dtest=Lz4ArchiveTest,Lz4VolumeIntegrationTest,NativeArchivePasswordTest,EncryptArchiveStagingTest,ArchiveProgressPhaseTest,SplitRoundtripTest", "test"])
    run([maven, "-q", "-Dtest=Lz4InteropTest#desktopCorpusAndDesktopSelfRead", "-Dlz4.interop.generate=true", "-Dlz4.real.file=" + str(args.source.resolve()), "test"])
    wrapper = ROOT / "android" / ("gradlew.bat" if os.name == "nt" else "gradlew")
    run([wrapper, ":app:assembleDebug", ":app:assembleDebugAndroidTest", ":app:testDebugUnitTest", "--console=plain"], cwd=ROOT / "android")
    run([wrapper, ":shared-test:test", "--tests", "*Lz4ArchiveTest", "--tests", "*Lz4VolumeIntegrationTest", "--tests", "*EncryptArchiveStagingTest", "--console=plain"], cwd=ROOT / "android")
    run(adb + ["install", "-r", str(ROOT / "android/app/build/outputs/apk/debug/app-debug.apk")])
    run(adb + ["install", "-r", str(ROOT / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk")])
    transfer_to_app(adb, ROOT / "target/lz4-interop/desktop")
    tests = "hbnu.project.ergoutreecrypt.android.Lz4ArchiveUiTest,hbnu.project.ergoutreecrypt.android.Lz4MediaArchiveTest,hbnu.project.ergoutreecrypt.android.Lz4InteropTest"
    result = subprocess.run(adb + ["shell", "am", "instrument", "-w", "-e", "class", tests, PACKAGE + ".test/androidx.test.runner.AndroidJUnitRunner"], capture_output=True, text=True)
    output = ROOT / "target/lz4-interop"
    (output / "android-instrumentation.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout)
    if result.returncode or "FAILURES!!!" in result.stdout or "OK (" not in result.stdout:
        raise RuntimeError("Android instrumentation failed; see target/lz4-interop/android-instrumentation.log")
    mobile = output / "android"
    transfer_from_app(adb, mobile)
    run([maven, "-q", "-Dtest=Lz4InteropTest#desktopCorpusRestoresOnDesktop+androidCorpusRestoresOnDesktop", "-Dlz4.interop.desktop=" + str(output / "desktop"), "-Dlz4.interop.android=" + str(mobile), "test"])
    with args.source.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    print("All four directions verified for 12 scenarios each. Source SHA-256:", digest)

if __name__ == "__main__":
    main()
