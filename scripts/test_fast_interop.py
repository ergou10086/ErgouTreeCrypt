#!/usr/bin/env python3
"""在实际桌面 JVM 与 Android ART 间验证 FAST 四组合的认证和解密，共八方向。

语料和设备私有目录均为本次独占，退出时清理；正式测试源码与本入口保留。
示例：python scripts/test_fast_interop.py --adb PATH --serial emulator-5554
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import uuid

from test_split_interop import upload, download, run, ROOT, PACKAGE


def main():
    """构建、搬运和验证产物，仅操作本次随机生成的目录。"""
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default=shutil.which('adb'))
    parser.add_argument('--serial')
    parser.add_argument('--source', type=Path, default=ROOT/'src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a')
    parser.add_argument('--report', type=Path, help='可选的纯文本验证记录，不保留密文和明文语料')
    parser.add_argument('--skip-build', action='store_true')
    args = parser.parse_args()
    maven = shutil.which('mvn')
    if not args.adb or not maven or not args.source.is_file():
        parser.error('需要 adb、Maven 和真实源文件')
    adb = [args.adb] + (['-s', args.serial] if args.serial else [])
    name = 'fast-interop-' + uuid.uuid4().hex
    remote = 'files/' + name
    transcript = []
    try:
        with tempfile.TemporaryDirectory(prefix='fast-interop-', dir=ROOT/'target') as temporary:
            work = Path(temporary)
            corpus = work/'desktop'
            common = ['-q', '-DargLine=-Xmx1536m', '-Dfast.interop.root='+str(corpus)]
            run([maven, *common, '-Dtest=FastInteropTest#desktopProducerAndReader', '-Dfast.interop.generate=true', '-Dfast.interop.source='+str(args.source.resolve()), 'test'])
            transcript.append('PASS D→D：独立认证、默认解密、逐字节与 SHA-256、攻击拒绝')
            wrapper = ROOT/'android'/('gradlew.bat' if os.name == 'nt' else 'gradlew')
            if not args.skip_build:
                run([wrapper, ':app:assembleDebug', ':app:assembleDebugAndroidTest', '--console=plain'], cwd=ROOT/'android')
            run(adb+['install', '-r', ROOT/'android/app/build/outputs/apk/debug/app-debug.apk'])
            run(adb+['install', '-r', ROOT/'android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'])
            upload(adb, corpus, remote+'/desktop')
            result = subprocess.run(adb+['shell', 'am', 'instrument', '-w', '-e', 'class', 'hbnu.project.ergoutreecrypt.android.FastInteropTest', '-e', 'fastRoot', name, PACKAGE+'.test/androidx.test.runner.AndroidJUnitRunner'], capture_output=True, text=True, encoding='utf-8', errors='replace')
            transcript.append(result.stdout+result.stderr)
            print(result.stdout, flush=True)
            if result.returncode or 'FAILURES!!!' in result.stdout or 'OK (' not in result.stdout:
                raise RuntimeError('实际 ART 测试失败')
            transcript.append('PASS D→A、A→A：独立认证、默认解密、逐字节与 SHA-256、攻击拒绝')
            download(adb, work/'android', remote+'/android')
            run([maven, *common, '-Dtest=FastInteropTest#desktopReadsAndroid', '-Dfast.interop.android=true', '-Dfast.interop.ciphers='+str(work/'android'), 'test'])
            transcript.append('PASS A→D：独立认证、默认解密、逐字节与 SHA-256、攻击拒绝')
            transcript.append('PASS：四种生产／读取组合 × 独立认证和默认解密 = 八方向；每种含八个文件及十九组攻击。')
    finally:
        cleanup = subprocess.run(adb+['shell', 'run-as', PACKAGE, 'rm', '-rf', remote], capture_output=True, text=True)
        if cleanup.returncode:
            transcript.append('设备私有临时目录清理失败：'+remote)
        if args.report:
            args.report.write_text('\n'.join(transcript)+'\n', encoding='utf-8')
    print('\n'.join(transcript[-2:]))


if __name__ == '__main__':
    main()
