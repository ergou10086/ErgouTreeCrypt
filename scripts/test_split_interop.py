#!/usr/bin/env python3
"""Real desktop JVM <-> Android ART split regression: four decrypt + four verify directions.
Use an existing connected emulator/device. The script installs debug/test APKs only.
Example: python scripts/test_split_interop.py --adb PATH --slow
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[1]
PACKAGE='hbnu.project.ergoutreecrypt.debug'

def run(args,cwd=ROOT):
    subprocess.run([str(x) for x in args],cwd=cwd,check=True)

def upload(adb,source,destination="files/split-interop/desktop"):
    run(adb+['shell','run-as',PACKAGE,'mkdir','-p',destination])
    proc=subprocess.Popen(adb+['exec-in','run-as',PACKAGE,'tar','-xf','-','-C',destination],stdin=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdin,mode='w|') as archive:
            for file in sorted(source.rglob('*')):
                if file.is_file():archive.add(file,arcname=file.relative_to(source).as_posix())
    except BaseException:
        proc.terminate();proc.wait();raise
    finally:proc.stdin.close()
    if proc.wait()!=0:raise RuntimeError('Split corpus upload failed')

def download(adb,output,source="files/split-interop/android"):
    output.mkdir(parents=True,exist_ok=True)
    proc=subprocess.Popen(adb+['exec-out','run-as',PACKAGE,'tar','-cf','-','-C',source,'.'],stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=proc.stdout,mode='r|') as archive:
            for entry in archive:
                target=(output/entry.name).resolve()
                if not target.is_relative_to(output.resolve()):raise RuntimeError('Unsafe artifact path')
                if entry.isdir():target.mkdir(parents=True,exist_ok=True)
                elif entry.isfile():
                    target.parent.mkdir(parents=True,exist_ok=True)
                    with archive.extractfile(entry) as src,target.open('wb') as dst:shutil.copyfileobj(src,dst)
                else:raise RuntimeError('Unsupported artifact entry')
    except BaseException:
        proc.terminate();proc.wait();raise
    finally:proc.stdout.close()
    if proc.wait()!=0:raise RuntimeError('Split corpus download failed')

def main():
    sys.stdout.reconfigure(encoding='utf-8');sys.stderr.reconfigure(encoding='utf-8')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb',default=shutil.which('adb'))
    parser.add_argument('--serial')
    parser.add_argument('--source',type=Path,default=ROOT/'src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a')
    parser.add_argument('--slow',action='store_true',help='Include legacy and dual deniability (1 GiB KDF)')
    parser.add_argument('--reuse-desktop',action='store_true',help='Reuse the already generated desktop corpus')
    parser.add_argument('--resume-android',action='store_true',help='Resume an already generated 40-case ART corpus after interruption')
    parser.add_argument('--skip-build',action='store_true',help='Use already built debug and test APKs')
    args=parser.parse_args()
    maven=shutil.which('mvn')
    if not args.adb or not maven or not args.source.is_file():parser.error('adb, Maven and a real source file are required')
    adb=[args.adb]+(['-s',args.serial] if args.serial else [])
    output=ROOT/'target/split-interop'
    if not args.reuse_desktop:
        run([maven,'-q','-Dtest=SplitCompletenessTest,SplitterTest,SplitRoundtripTest,SplitInteropTest#optionAndArchiveMatrix','test'])
        run([maven,'-q','-Dtest=SplitInteropTest#generateDesktopCorpus','-Dsplit.interop.generate=true','-Dsplit.real.file='+str(args.source.resolve()),'-Dsplit.interop.slow='+str(args.slow).lower(),'-DargLine=-Xmx1536m','test'])
    elif not (output/'desktop/manifest.properties').is_file():parser.error('No desktop corpus to reuse')
    else:
        run([maven,'-q','-Dtest=SplitInteropTest#verifyDesktopCorpus','-Dsplit.interop.verifyDesktop=true','-DargLine=-Xmx1536m','test'])
    wrapper=ROOT/'android'/('gradlew.bat' if os.name=='nt' else 'gradlew')
    if not args.skip_build:
        run([wrapper,':app:assembleDebug',':app:assembleDebugAndroidTest',':shared-test:test','--tests','*SplitCompletenessTest','--tests','*SplitRoundtripTest','--tests','*SplitInteropTest.optionAndArchiveMatrix','--console=plain'],cwd=ROOT/'android')
    run(adb+['install','-r',ROOT/'android/app/build/outputs/apk/debug/app-debug.apk'])
    run(adb+['install','-r',ROOT/'android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'])
    upload(adb,output/'desktop')
    tests='hbnu.project.ergoutreecrypt.android.SplitInteropTest,hbnu.project.ergoutreecrypt.android.SplitSafTest,hbnu.project.ergoutreecrypt.android.SplitDecryptUiTest'
    if args.resume_android:
        if not args.slow:parser.error('--resume-android requires --slow and a 40-case ART corpus')
        tests=tests.replace('hbnu.project.ergoutreecrypt.android.SplitInteropTest','hbnu.project.ergoutreecrypt.android.SplitResumeTest')
    result=subprocess.run(adb+['shell','am','instrument','-w','-e','class',tests,'-e','splitSlow',str(args.slow).lower(),PACKAGE+'.test/androidx.test.runner.AndroidJUnitRunner'],capture_output=True,text=True,encoding='utf-8',errors='replace')
    (output/'android-instrumentation.log').write_text(result.stdout+result.stderr,encoding='utf-8')
    print(result.stdout)
    if result.returncode or 'FAILURES!!!' in result.stdout or 'OK (' not in result.stdout:raise RuntimeError('Android instrumentation failed; see target/split-interop/android-instrumentation.log')
    if args.slow:
        extra=subprocess.run(adb+['shell','am','instrument','-w','-e','class','hbnu.project.ergoutreecrypt.android.SplitAdvancedTest','-e','splitSlow','true',PACKAGE+'.test/androidx.test.runner.AndroidJUnitRunner'],capture_output=True,text=True,encoding='utf-8',errors='replace')
        (output/'android-advanced.log').write_text(extra.stdout+extra.stderr,encoding='utf-8')
        print(extra.stdout)
        if extra.returncode or 'FAILURES!!!' in extra.stdout or 'OK (' not in extra.stdout:raise RuntimeError('Android advanced split tests failed')
    download(adb,output/'android')
    run([maven,'-q','-Dtest=SplitInteropTest#verifyAndroidCorpus','-Dsplit.interop.android='+str(output/'android'),'-DargLine=-Xmx1536m','test'])
    if args.slow:
        run([maven,'-q','-Dtest=SplitInteropTest#deniabilityDecoyBranches+dualDeniabilityRsRecovery','-Dsplit.interop.decoy=true','-Dsplit.interop.rsDual=true','-DargLine=-Xmx1536m','test'])
    print('PASS: all eight split decrypt/verify directions; exact bytes and SHA-256 checked.')

if __name__=='__main__':main()