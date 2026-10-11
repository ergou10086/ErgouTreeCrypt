"""通过验收应用中转语料，支持不可调试、实际启用 R8 的验收包。"""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile
import hashlib
import time
from test_split_interop import ROOT

PACKAGE = 'hbnu.project.ergoutreecrypt.fastvalidation'
FOREGROUND = False
AUTHORITY = 'content://hbnu.project.ergoutreecrypt.fast.tests/relay/'


def instrument(adb, arguments, foreground=False):
    """可选保持验收应用前台，避免设备的后台冻结策略中断大型测试。"""
    command = adb+['shell','am','instrument','-w',*arguments,
        PACKAGE+'.test/androidx.test.runner.AndroidJUnitRunner']
    if not foreground:
        return subprocess.run(command,capture_output=True,text=True,encoding='utf-8',errors='replace')
    previous = subprocess.run(adb+['shell','pidof',PACKAGE],capture_output=True,text=True).stdout.strip()
    process = subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        text=True,encoding='utf-8',errors='replace')
    try:
        deadline = time.monotonic()+30
        while process.poll() is None and time.monotonic() < deadline:
            current = subprocess.run(adb+['shell','pidof',PACKAGE],capture_output=True,text=True).stdout.strip()
            if current and current != previous:
                launched = subprocess.run(adb+['shell','am','start','-W','-n',
                    PACKAGE+'/hbnu.project.ergoutreecrypt.android.MainActivity'],capture_output=True,text=True)
                if launched.returncode or 'Error' in launched.stdout+launched.stderr:
                    raise RuntimeError('无法打开验收应用：'+launched.stdout+launched.stderr)
                break
            time.sleep(0.2)
        stdout,stderr = process.communicate()
        return subprocess.CompletedProcess(command,process.returncode,stdout,stderr)
    except Exception:
        subprocess.run(adb+['shell','am','force-stop',PACKAGE],check=True)
        process.communicate()
        raise


def invoke(adb, operation, path):
    """仅允许随机目录，严格检查 instrumentation 的实际测试结果。"""
    if not re.fullmatch(r'files/fast-(interop|benchmark)-[a-f0-9]{32}(/(desktop|android|results))?', path):
        raise ValueError('非法测试目录')
    result = instrument(adb,['-e','class',
        'hbnu.project.ergoutreecrypt.android.FastTransferTest','-e','transferOperation',operation,
        '-e','transferPath',path],FOREGROUND)
    if result.returncode or 'OK (1 test)' not in result.stdout or 'FAILURES!!!' in result.stdout:
        raise RuntimeError(result.stdout+result.stderr)


def upload(adb, source, destination):
    """上传真实字节后，由 instrumentation 解包进目标应用私有目录。"""
    if not re.fullmatch(r'files/fast-(interop|benchmark)-[a-f0-9]{32}(/(desktop|android|results))?', destination):
        raise ValueError('非法测试目录')
    name = destination.split('/')[1]
    with tempfile.TemporaryDirectory(prefix='fast-transfer-',dir=ROOT/'target') as directory:
        archive = Path(directory)/'relay.zip'
        with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED,allowZip64=True) as zip:
            for file in sorted(source.rglob('*')):
                if file.is_file(): zip.write(file,file.relative_to(source).as_posix())
        remote = '/data/local/tmp/'+name+'.zip'
        try:
            subprocess.run(adb+['push',str(archive),remote],check=True)
            # 使用设备本地重定向，避免 Windows adb shell 的 stdin 在大流上提前关闭。
            subprocess.run(adb+['shell','content write --uri '+AUTHORITY+name+'.zip < '+remote],check=True)
            returned = Path(directory)/'returned.zip'
            with returned.open('wb') as stream:
                subprocess.run(adb+['exec-out','content','read','--uri',AUTHORITY+name+'.zip'],stdout=stream,check=True)
            with archive.open('rb') as left,returned.open('rb') as right:
                if hashlib.file_digest(left,'sha256').digest() != hashlib.file_digest(right,'sha256').digest():
                    raise RuntimeError('设备中转 ZIP 的 SHA-256 不同')
        finally:
            subprocess.run(adb+['shell','rm','-f',remote],check=True)
    invoke(adb,'upload',destination)


def download(adb, output, source):
    """下载后逐项检查路径，不允许 ZIP 项写到目标目录之外。"""
    if not re.fullmatch(r'files/fast-(interop|benchmark)-[a-f0-9]{32}(/(desktop|android|results))?', source):
        raise ValueError('非法测试目录')
    invoke(adb,'download',source)
    name = source.split('/')[1]
    output.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='fast-transfer-',dir=ROOT/'target') as directory:
        archive = Path(directory)/'relay.zip'
        with archive.open('wb') as stream:
            subprocess.run(adb+['exec-out','content','read','--uri',AUTHORITY+name+'.zip'],stdout=stream,check=True)
        with zipfile.ZipFile(archive) as zip:
            for entry in zip.infolist():
                target = (output/entry.filename).resolve()
                if not target.is_relative_to(output.resolve()): raise RuntimeError('中转 ZIP 路径越界')
                if entry.is_dir(): target.mkdir(parents=True,exist_ok=True)
                else:
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with zip.open(entry) as src,target.open('wb') as dst: shutil.copyfileobj(src,dst)


def cleanup(adb, path):
    """删除本次独占目录和中转 ZIP。"""
    invoke(adb,'cleanup',path)
