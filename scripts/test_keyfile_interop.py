#!/usr/bin/env python3
"""密钥文件真实 JVM/ART 八方向回归；独占临时数据位于 D 盘仓库 target，退出清理。

保留本可复用入口及正式测试源码。使用 --slow 验证生产 KDF 与旧可否认层。
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'hbnu.project.ergoutreecrypt.debug'


def main():
    """构建双方、交换实际字节、校验所有方向，并清理本次独占语料。"""
    sys.stdout.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default=shutil.which('adb'))
    parser.add_argument('--serial', required=True)
    parser.add_argument('--source', type=Path, default=ROOT/'src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a')
    parser.add_argument('--slow', action='store_true')
    parser.add_argument('--batch', action='store_true', help='补充十二目录配置和五个生产 KDF 档位的八方向')
    parser.add_argument('--batch-quick', action='store_true', help='目录问题定位时跳过耗时的生产 KDF 档位')
    parser.add_argument('--batch-repeat', type=int, default=1, help='桌面重复读取同一份 Android 目录密文的次数')
    parser.add_argument('--snapshot', type=Path, help='诊断时复制语料到一个尚不存在的目录，由调用者负责清理')
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if not 1 <= args.batch_repeat <= 100:
        parser.error('--batch-repeat 必须介于 1 和 100')
    if args.batch_quick and not args.batch:
        parser.error('--batch-quick 只能与 --batch 一起使用')
    if args.snapshot and args.snapshot.exists():
        parser.error('--snapshot 必须指向尚不存在的目录')
    test_class = 'KeyfileBatchInteropTest' if args.batch else 'KeyfileInteropTest'
    maven = shutil.which('mvn')
    if not args.adb or not maven or not args.source.is_file():
        parser.error('需要 adb、Maven、已启动的设备以及真实源文件')
    adb = [args.adb, '-s', args.serial]
    name = 'keyfile-interop-' + uuid.uuid4().hex
    remote = 'files/' + name
    assert re.fullmatch(r'files/keyfile-interop-[a-f0-9]{32}', remote)
    transcript = []
    uploaded = False
    target = ROOT/'target'
    target.mkdir(exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix=name+'-', dir=target) as temporary:
            work = Path(temporary)
            tmp = work/'tmp'
            tmp.mkdir()
            environment = os.environ.copy()
            environment.update(TEMP=str(tmp), TMP=str(tmp))
            common = ['-q', '-Dkeyfile.root='+str(work), '-Dkeyfile.slow='+str(args.slow).lower(),
                      '-Dkeyfile.profiles='+str(not args.batch_quick).lower(),
                      '-Dkeyfile.batch.repeats='+str(args.batch_repeat),
                      '-DargLine=-Xmx1536m -Djava.io.tmpdir='+str(tmp)]

            def run(command, label, cwd=ROOT):
                log = work/(label+'.log')
                print('RUN '+label, flush=True)
                with log.open('wb') as output:
                    result = subprocess.run([str(x) for x in command], cwd=cwd, env=environment, stdout=output, stderr=subprocess.STDOUT)
                text = log.read_text(encoding='utf-8', errors='replace')
                transcript.append(label+'\n'+text)
                if result.returncode:
                    print(text[-10000:], flush=True)
                    raise RuntimeError(label+' failed with exit '+str(result.returncode))
                return text

            if not args.skip_build:
                run([ROOT/'android/gradlew.bat' if os.name == 'nt' else ROOT/'android/gradlew',
                     ':app:assembleDebug', ':app:assembleDebugAndroidTest', '--no-daemon', '--console=plain',
                     '-Pkotlin.compiler.execution.strategy=in-process',
                     '-Dorg.gradle.jvmargs=-Xmx4096m -Dfile.encoding=UTF-8 -Djava.io.tmpdir='+str(tmp)], 'android-build', ROOT/'android')
            run([maven, *common, '-Dtest=KeyfileProcessorTest,KeyfileSafetyTest,FastCapabilitiesTest,'+test_class+'#desktopProducerAndReader',
                 '-Dkeyfile.generate=true', '-Dkeyfile.source='+str(args.source.resolve()), 'test'], 'desktop-produce-read')
            transcript.append('PASS D→D 认证+解密')
            with args.source.open('rb') as stream:
                transcript.append('SOURCE SHA-256 '+hashlib.file_digest(stream, 'sha256').hexdigest())
            for apk in ['debug/app-debug.apk', 'androidTest/debug/app-debug-androidTest.apk']:
                run(adb+['install', '-r', ROOT/'android/app/build/outputs/apk'/apk], 'install-'+Path(apk).name)
            archive = work/'upload.tar'
            with tarfile.open(archive, 'w') as output:
                for folder in ['corpus', 'desktop']:
                    output.add(work/folder, arcname=folder)
            device_tar = '/data/local/tmp/'+name+'.tar'
            uploaded = True
            try:
                run(adb+['push', archive, device_tar], 'upload')
                run(adb+['shell', 'run-as', PACKAGE, 'mkdir', '-p', remote], 'device-mkdir')
                run(adb+['shell', 'cat '+device_tar+' | run-as '+PACKAGE+' tar -xf - -C '+remote], 'device-extract')
            finally:
                subprocess.run(adb+['shell', 'rm', '-f', device_tar], check=True)
            archive.unlink()
            result = run(adb+['shell', 'am', 'instrument', '-w', '-e', 'class',
                             'hbnu.project.ergoutreecrypt.android.'+test_class+',hbnu.project.ergoutreecrypt.android.KeyfileSafetyDeviceTest,hbnu.project.ergoutreecrypt.android.KeyfileSafTest', '-e', 'keyfileRoot', name,
                             '-e', 'keyfileSlow', str(args.slow).lower(), '-e', 'keyfileProfiles', str(not args.batch_quick).lower(),
                             PACKAGE+'.test/androidx.test.runner.AndroidJUnitRunner'], 'android-instrumentation')
            if 'OK (6 tests)' not in result or 'FAILURES!!!' in result or 'INSTRUMENTATION_FAILED' in result:
                print(result[-10000:], flush=True)
                raise RuntimeError('实际 ART 认证/解密失败')
            transcript.append('PASS D→A、A→A 认证+解密')
            archive = work/'download.tar'
            with archive.open('wb') as output:
                subprocess.run(adb+['exec-out', 'run-as', PACKAGE, 'tar', '-cf', '-', '-C', remote, 'android'], stdout=output, check=True)
            with tarfile.open(archive) as input:
                for entry in input:
                    destination = (work/entry.name).resolve()
                    if not destination.is_relative_to(work.resolve()) or not (entry.isdir() or entry.isfile()):
                        raise RuntimeError('不安全的设备产物路径')
                    if entry.isdir(): destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        with input.extractfile(entry) as source, destination.open('wb') as output:
                            shutil.copyfileobj(source, output)
            if args.snapshot:
                args.snapshot.mkdir(parents=True, exist_ok=False)
                for folder in ['corpus', 'desktop', 'android']:
                    shutil.copytree(work/folder, args.snapshot/folder)
            run([maven, *common, '-Dtest='+test_class+'#desktopReadsAndroid', '-Dkeyfile.android=true', 'test'], 'desktop-read-android')
            transcript.append('PASS A→D 认证+解密')
            for producer in ['desktop', 'android']:
                transcript.append(producer+' MANIFEST\n'+(work/producer/'manifest.properties').read_text(encoding='latin-1'))
            transcript.append('PASS 八方向，每方向 '+('12目录' if args.batch and args.batch_quick else '17（12目录+5生产KDF）' if args.batch else '172' if args.slow else '164')+' 个有效组合；逐字节、SHA-256 和错误凭据拒绝。')
    except BaseException as error:
        transcript.append('FAIL '+str(error))
        raise
    finally:
        try:
            if uploaded:
                subprocess.run(adb+['shell', 'run-as', PACKAGE, 'rm', '-rf', remote], check=True)
                transcript.append('CLEANED '+remote)
        finally:
            if args.report:
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text('\n'.join(transcript)+'\n', encoding='utf-8')
    print(transcript[-2], flush=True)


if __name__ == '__main__':
    main()
