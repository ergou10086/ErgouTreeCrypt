#!/usr/bin/env python3
"""构建包含 JDK 的桌面应用镜像，让自动模块依赖通过 classpath 正常加载。

用法：python scripts/build_desktop.py --output target/desktop-image
输出目录必须不存在；脚本不会清空已有镜像或用户文件。
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def run(args):
    """执行参数列表形式的命令并检查结果。"""
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def main():
    """打包当前平台应用镜像，保留原有 Maven 模块化编译。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'target/desktop-image')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists(): parser.error('输出目录已存在，请指定新目录。')
    java_home = Path(os.environ['JAVA_HOME'])
    suffix = '.exe' if os.name == 'nt' else ''
    maven = shutil.which('mvn')
    if not maven: parser.error('找不到 Maven。')
    version = ET.parse(ROOT / 'pom.xml').getroot().find('{http://maven.apache.org/POM/4.0.0}version').text
    run([maven, '-q', '-DskipTests', 'package'])
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='desktop-packaging-', dir=output.parent) as temporary:
        work = Path(temporary)
        app = work / 'app'
        app.mkdir()
        run([maven, '-q', 'dependency:copy-dependencies', '-DincludeScope=runtime', '-DoutputDirectory=' + str(app)])
        jar_name = 'ErgouTreeCrypt-' + version + '.jar'
        shutil.copy2(ROOT / 'target' / jar_name, app / jar_name)
        runtime = work / 'runtime'
        modules = 'java.se,jdk.crypto.ec,jdk.unsupported,jdk.charsets,jdk.zipfs'
        run([java_home / 'bin' / ('jlink' + suffix), '--add-modules', modules,
             '--output', runtime, '--strip-debug', '--no-header-files', '--no-man-pages'])
        images = work / 'images'
        run([java_home / 'bin' / ('jpackage' + suffix), '--type', 'app-image', '--name', 'ErgouTreeCrypt',
             '--input', app, '--main-jar', jar_name, '--main-class', 'hbnu.project.ergoutreecrypt.Launcher',
             '--app-version', version, '--runtime-image', runtime, '--dest', images])
        image = images / ('ErgouTreeCrypt.app' if os.name == 'posix' and os.uname().sysname == 'Darwin' else 'ErgouTreeCrypt')
        shutil.move(str(image), output)
    print('桌面镜像：' + str(output))


if __name__ == '__main__': main()
