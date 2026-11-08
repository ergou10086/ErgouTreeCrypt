#!/usr/bin/env python3
"""下载改名专项：真实桌面 JVM 与 Android ART 的四种生产／读取组合，各自认证与解密（八方向）。

保留可复用入口及测试源码；生成的语料和日志位于 target/split-downloads。
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
from test_split_interop import ROOT, PACKAGE, run, upload, download


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=shutil.which("adb"))
    parser.add_argument("--serial")
    parser.add_argument("--source", type=Path, default=ROOT / "src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    maven = shutil.which("mvn")
    if not args.adb or not maven or not args.source.is_file():
        parser.error("adb, Maven and a readable source file are required")
    adb = [args.adb] + (["-s", args.serial] if args.serial else [])
    output = ROOT / "target/split-downloads"
    output.mkdir(parents=True, exist_ok=True)
    run([maven, "-q", "-Dtest=SplitDownloadTest#desktopCorpus,SplitterTest,SplitCompletenessTest,SplitRoundtripTest,SplitMetadataTest#embeddedBoundaries,FileInputGuardTest",
         "-Dsplit.download.generate=true", "-Dsplit.real.file=" + str(args.source.resolve()), "test"])
    wrapper = ROOT / "android" / ("gradlew.bat" if os.name == "nt" else "gradlew")
    if not args.skip_build:
        run([wrapper, ":app:assembleDebug", ":app:assembleDebugAndroidTest", "-Pkotlin.incremental=false", "--console=plain"], cwd=ROOT / "android")
    run(adb + ["install", "-r", ROOT / "android/app/build/outputs/apk/debug/app-debug.apk"])
    run(adb + ["install", "-r", ROOT / "android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"])
    upload(adb, output / "desktop", "files/split-downloads/desktop")
    # 部分真机系统限制测试 APK 的后台冷启动，先由 shell 激活只读测试提供者。
    subprocess.run(adb + ["shell", "content", "query", "--uri",
                          "content://hbnu.project.ergoutreecrypt.split.tests/document/root%2FA%2Fsame.bin.ergou.0"],
                   check=True, stdout=subprocess.DEVNULL)
    tests = ",".join("hbnu.project.ergoutreecrypt.android." + name for name in
                     ["SplitDownloadTest#desktopOnArtAndArtOnArt", "SplitSafTest", "SplitDecryptUiTest"])
    result = subprocess.run(adb + ["shell", "am", "instrument", "-w", "-e", "class", tests,
                                  PACKAGE + ".test/androidx.test.runner.AndroidJUnitRunner"],
                            capture_output=True, text=True, encoding="utf-8", errors="replace")
    (output / "android-instrumentation.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    print(result.stdout)
    if result.returncode or "FAILURES!!!" in result.stdout or "OK (" not in result.stdout:
        raise RuntimeError("Android download tests failed; see target/split-downloads/android-instrumentation.log")
    download(adb, output / "android", "files/split-downloads/android")
    run([maven, "-q", "-Dtest=SplitDownloadTest#androidCorpus", "-Dsplit.download.android=true", "test"])
    print("PASS: all eight download split authenticate/decrypt directions; 36 case pairs per runtime combination, exact plaintext bytes checked.")


if __name__ == "__main__":
    main()
