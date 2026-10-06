#!/usr/bin/env python3
"""Test both split metadata settings in eight desktop / native Android directions.
Keeps only reusable test code in Git; generated corpora and logs live under target/.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from test_split_interop import ROOT, PACKAGE, run, upload, download


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=shutil.which("adb"))
    parser.add_argument("--serial")
    parser.add_argument("--source", type=Path, default=ROOT / "src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a")
    parser.add_argument("--reuse-desktop", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    maven = shutil.which("mvn")
    if not maven or not args.adb or not args.source.is_file():
        parser.error("Maven, adb and a real test file are required")
    version = ET.parse(ROOT / "pom.xml").getroot().find("{http://maven.apache.org/POM/4.0.0}version").text
    output = ROOT / "target/split-mode"
    output.mkdir(parents=True, exist_ok=True)
    if not args.reuse_desktop:
        run([maven, "-q", "-Dtest=SplitModeTest#generateDesktop,SplitSettingsUiTest", "-Dsplit.mode.generate=true", "-Dergoutreecrypt.uiTests=true", "-Dsplit.expected.version=" + version, "-Dsplit.real.file=" + str(args.source.resolve()), "-DargLine=-Xmx1536m", "test"])
    elif not (output / "desktop/manifest.properties").is_file():
        parser.error("No desktop corpus to reuse")
    for name in ["fileops.SplitModeTest", "ui.support.SplitSettingsUiTest"]:
        shutil.copy2(ROOT / ("target/surefire-reports/TEST-hbnu.project.ergoutreecrypt." + name + ".xml"), output / ("desktop-" + name + ".xml"))
    if not args.skip_build:
        run([ROOT / "android" / ("gradlew.bat" if os.name == "nt" else "gradlew"), ":app:assembleDebug", ":app:assembleDebugAndroidTest", "--console=plain"], cwd=ROOT / "android")
    adb = [args.adb] + (["-s", args.serial] if args.serial else [])
    run(adb + ["install", "-r", ROOT / "android/app/build/outputs/apk/debug/app-debug.apk"])
    run(adb + ["install", "-r", ROOT / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"])
    upload(adb, output / "desktop", "files/split-mode/desktop")
    tests = "hbnu.project.ergoutreecrypt.android.SplitModeTest,hbnu.project.ergoutreecrypt.android.SplitSettingsUiTest"
    result = subprocess.run(adb + ["shell", "am", "instrument", "-w", "-e", "class", tests, "-e", "expectedVersion", version, PACKAGE + ".test/androidx.test.runner.AndroidJUnitRunner"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    (output / "android-instrumentation.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout)
    if result.returncode or "FAILURES!!!" in result.stdout or "OK (" not in result.stdout:
        raise RuntimeError("Scoped Android format settings regression failed")
    download(adb, output / "android", "files/split-mode/android")
    run([maven, "-q", "-Dtest=SplitModeTest#verifyAndroid", "-Dsplit.mode.android=true", "-DargLine=-Xmx1536m", "test"])
    shutil.copy2(ROOT / "target/surefire-reports/TEST-hbnu.project.ergoutreecrypt.fileops.SplitModeTest.xml", output / "android-on-desktop.xml")
    print("PASS: both formats, seven cases each, all eight authenticate/decrypt directions, six missing-volume scenarios per pairing, persistent desktop and Compose settings, version " + version)


if __name__ == "__main__":
    main()
