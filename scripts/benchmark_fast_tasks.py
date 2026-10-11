#!/usr/bin/env python3
"""运行完整 FAST/标准任务基准；桌面发行 JVM 与可选真实 Android，保留 CSV，清理明密文。

运行前须构建桌面镜像、test-compile，并在设备安装包含 FastBenchmarkTest 的验收 APK。
输出目录必须是新目录；所有临时输入、设备目录仅属于本次调用。
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid
import test_split_interop as transfer
import fast_device_transfer as device


def main():
    """顺序测试两端，避免同机 CPU 竞争污染性能数据。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--desktop-image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repeat', type=int, default=20)
    parser.add_argument('--adb')
    parser.add_argument('--serial')
    parser.add_argument('--android-package', default='hbnu.project.ergoutreecrypt.fastvalidation')
    parser.add_argument('--foreground', action='store_true', help='设备计时期间保持验收应用前台')
    parser.add_argument('--large', action='store_true', help='两端验证真实写入超过 4 GiB 的文件，需约 13 GiB 空间')
    args = parser.parse_args()
    if not args.source.is_file() or not 1 <= args.repeat <= 100:
        parser.error('需要真实源文件，重复次数须为 1—100')
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='fast-benchmark-', dir=transfer.ROOT/'target') as temporary:
        work = Path(temporary)
        input_file = work/'input.bin'
        java = args.desktop_image/'runtime/bin'/('java.exe' if os.name == 'nt' else 'java')
        classpath = str(transfer.ROOT/'target/test-classes')+os.pathsep+str(args.desktop_image/'app/*')
        if args.large:
            transfer.run([java,'-Xmx1536m','-cp',classpath,'hbnu.project.ergoutreecrypt.volume.FastLargeFileSupport',
                args.source,args.output/'desktop'])
        else:
            with input_file.open('xb') as out:
                for _ in range(args.repeat):
                    with args.source.open('rb') as source:
                        shutil.copyfileobj(source, out, 1024*1024)
            transfer.run([java,'-Xmx1536m','-cp',classpath,'hbnu.project.ergoutreecrypt.volume.FastTaskBenchmark',
                input_file,args.output/'desktop','262144','3','4'])
        if args.adb:
            device.PACKAGE = args.android_package
            device.FOREGROUND = args.foreground
            adb = [args.adb]+(['-s',args.serial] if args.serial else [])
            name = 'fast-benchmark-'+uuid.uuid4().hex
            remote = 'files/'+name
            upload = work/'upload'
            upload.mkdir()
            shutil.copy2(args.source, upload/'source.bin')
            try:
                device.upload(adb, upload, remote)
                result = device.instrument(adb,['-e','class',
                    'hbnu.project.ergoutreecrypt.android.FastBenchmarkTest','-e','fastBenchmark','true',
                    '-e','fastRoot',name,'-e','repeat',str(args.repeat),
                    '-e','large',str(args.large).lower()], args.foreground)
                (args.output/'android-instrumentation.txt').write_text(result.stdout+result.stderr,encoding='utf-8')
                print(result.stdout,flush=True)
                if result.returncode or 'FAILURES!!!' in result.stdout or 'OK (' not in result.stdout:
                    raise RuntimeError('Android 完整任务性能入口失败')
                device.download(adb,args.output/'android',remote+'/results')
                if args.large:
                    def summary(path):
                        return dict(line.split('=',1) for line in path.read_text().splitlines())
                    desktop_result = summary(args.output/'desktop/large-result.txt')
                    android_result = summary(args.output/'android/large-result.txt')
                    if any(desktop_result[key] != android_result[key] for key in ('bytes','sha256')):
                        raise RuntimeError('两端超过 4 GiB 的真实输入摘要不同')
            finally:
                device.cleanup(adb,remote)


if __name__ == '__main__':
    main()
