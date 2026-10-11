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
import hashlib

from test_split_interop import run, ROOT
import fast_device_transfer as transfer
from fast_device_transfer import upload, download

PACKAGE = 'hbnu.project.ergoutreecrypt.debug'


def main():
    """构建、搬运和验证产物，仅操作本次随机生成的目录。"""
    global PACKAGE
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default=shutil.which('adb'))
    parser.add_argument('--serial')
    parser.add_argument('--source', type=Path, default=ROOT/'src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a')
    parser.add_argument('--report', type=Path, help='可选的纯文本验证记录，不保留密文和明文语料')
    parser.add_argument('--skip-build', action='store_true')
    parser.add_argument('--desktop-image', type=Path, help='使用该发行镜像内的 JVM 与运行时依赖')
    parser.add_argument('--android-build-type', choices=['debug', 'releaseValidation'], default='debug')
    parser.add_argument('--ui', action='store_true', help='同时执行独立 UI 用例，需保持设备解锁')
    parser.add_argument('--foreground', action='store_true', help='大型设备测试期间打开验收应用，避免后台冻结')
    parser.add_argument('--reuse-corpus', type=Path, help='复用已有语料并重新验证，需同时指定 desktop-image；不删除该目录')
    args = parser.parse_args()
    if args.reuse_corpus and not args.desktop_image:
        parser.error('复用语料需要发行 JVM')
    if args.android_build_type == 'releaseValidation':
        PACKAGE = 'hbnu.project.ergoutreecrypt.fastvalidation'
    transfer.PACKAGE = PACKAGE
    transfer.FOREGROUND = args.foreground
    maven = shutil.which('mvn')
    if not args.adb or not maven or not args.source.is_file():
        parser.error('需要 adb、Maven 和真实源文件')
    adb = [args.adb] + (['-s', args.serial] if args.serial else [])
    name = 'fast-interop-' + uuid.uuid4().hex
    remote = 'files/' + name
    transcript = []
    installed = False
    cleanup_error = None
    try:
        with tempfile.TemporaryDirectory(prefix='fast-interop-', dir=ROOT/'target') as temporary:
            work = Path(temporary)
            corpus = args.reuse_corpus.resolve() if args.reuse_corpus else work/'desktop'
            common = ['-q', '-DargLine=-Xmx1536m', '-Dfast.interop.root='+str(corpus)]
            if args.desktop_image:
                run([maven, '-q', '-DskipTests', 'test-compile'])
                desktop = [args.desktop_image/'runtime/bin'/('java.exe' if os.name == 'nt' else 'java'),
                    '-Xmx1536m', '-cp', str(ROOT/'target/test-classes')+os.pathsep+str(args.desktop_image/'app/*'),
                    'hbnu.project.ergoutreecrypt.volume.FastInteropCli']
                run(desktop+(['verify', corpus, corpus/'ciphers'] if args.reuse_corpus
                    else ['generate', corpus, args.source.resolve()]))
            else:
                run([maven, *common, '-Dtest=FastInteropTest#desktopProducerAndReader', '-Dfast.interop.generate=true', '-Dfast.interop.source='+str(args.source.resolve()), 'test'])
            transcript.append('PASS D→D：独立认证、默认解密、逐字节与 SHA-256、攻击拒绝')
            with args.source.open('rb') as stream:
                transcript.append('源文件 SHA-256：'+hashlib.file_digest(stream,'sha256').hexdigest())
            wrapper = ROOT/'android'/('gradlew.bat' if os.name == 'nt' else 'gradlew')
            if not args.skip_build:
                variant = args.android_build_type[0].upper()+args.android_build_type[1:]
                extra = ['-PfastReleaseTest'] if args.android_build_type != 'debug' else []
                run([wrapper, ':app:assemble'+variant, ':app:assemble'+variant+'AndroidTest', *extra, '--console=plain'], cwd=ROOT/'android')
            variant = args.android_build_type
            apk = ROOT/f'android/app/build/outputs/apk/{variant}/app-{variant}.apk'
            with apk.open('rb') as stream:
                transcript.append('APK '+variant+' SHA-256：'+hashlib.file_digest(stream,'sha256').hexdigest())
            run(adb+['install', '-r', ROOT/f'android/app/build/outputs/apk/{variant}/app-{variant}.apk'])
            run(adb+['install', '-r', ROOT/f'android/app/build/outputs/apk/androidTest/{variant}/app-{variant}-androidTest.apk'])
            installed = True
            run(adb+['shell', 'content', 'query', '--uri', 'content://hbnu.project.ergoutreecrypt.fast.tests/document/root'])
            upload(adb, corpus, remote+'/desktop')
            ui = 'FastModeUiTest' if variant == 'debug' else 'FastReleaseSmokeTest'
            selected = ['FastInteropTest','FastSafTest']+([ui] if args.ui else [])
            classes = ','.join('hbnu.project.ergoutreecrypt.android.'+name for name in selected)
            result = transfer.instrument(adb, ['-e','class',classes,'-e','fastRoot',name], args.foreground)
            transcript.append(result.stdout+result.stderr)
            print(result.stdout, flush=True)
            if result.returncode or 'FAILURES!!!' in result.stdout or 'OK (' not in result.stdout:
                raise RuntimeError('实际 ART 测试失败')
            transcript.append('PASS D→A、A→A：独立认证、默认解密、逐字节与 SHA-256、攻击拒绝')
            download(adb, work/'android', remote+'/android')
            if args.desktop_image:
                run(desktop+['verify', corpus, work/'android'])
            else:
                run([maven, *common, '-Dtest=FastInteropTest#desktopReadsAndroid', '-Dfast.interop.android=true', '-Dfast.interop.ciphers='+str(work/'android'), 'test'])
            transcript.append('PASS A→D：独立认证、默认解密、逐字节与 SHA-256、攻击拒绝')
            for platform, ciphers in [('desktop',corpus/'ciphers'),('android',work/'android')]:
                transcript.append(platform+' 生产端环境：\n'+(ciphers/'cipher-hashes.properties').read_text(encoding='latin-1'))
                timings = (ciphers/'archives/manifest.properties').read_text(encoding='latin-1').splitlines()
                transcript.append(platform+' 3,145,745 B 真实语料的归档完整任务耗时 ns（单轮，含 KDF）：\n'+
                    '\n'.join(line for line in timings if '.taskNanos=' in line))
            transcript.append('PASS：四种生产／读取组合 × 独立认证和默认解密 = 八方向；每种含十三个 FAST 文件、一个旧卷与混合批量、四十一组攻击、七类格式×前后归档×有无独立密码，以及实际 SAF 验证。')
            transcript.append('UI：'+('本轮执行通过' if args.ui else '本轮未执行，须单独记录结果'))
    except Exception as error:
        transcript.append('FAIL：'+str(error))
        raise
    finally:
        if installed:
            try:
                transfer.cleanup(adb, remote)
            except Exception as error:
                transcript.append('设备私有临时目录清理失败：'+remote+' '+str(error))
                cleanup_error = error
        if args.report:
            args.report.write_text('\n'.join(transcript)+'\n', encoding='utf-8')
        if cleanup_error:
            raise RuntimeError('设备私有目录清理失败：'+remote) from cleanup_error
    print('\n'.join(transcript[-2:]))


if __name__ == '__main__':
    main()
