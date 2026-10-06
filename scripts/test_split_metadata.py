#!/usr/bin/env python3
"""Scoped embedded split metadata regression: desktop/Android four producer-reader pairs,
with separate authentication and decryption in every pair (eight directions).
Uses the existing real test file and a connected ART emulator/device.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
from test_split_interop import ROOT,PACKAGE,run,upload,download


def main():
    sys.stdout.reconfigure(encoding='utf-8');sys.stderr.reconfigure(encoding='utf-8')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb',default=shutil.which('adb'))
    parser.add_argument('--serial')
    parser.add_argument('--source',type=Path,default=ROOT/'src/test/resources/filetest/[ひなみ桜花][2024-01-25].m4a')
    parser.add_argument('--legacy-fallback-only',action='store_true',help='Only the traditional disguise manifest fallback, in all eight directions')
    parser.add_argument('--slow',action='store_true',help='Include both deniability containers')
    parser.add_argument('--reuse-desktop',action='store_true',help='Resume the already verified desktop metadata corpus')
    parser.add_argument('--skip-build',action='store_true',help='Use already built APKs')
    parser.add_argument('--resume-android',action='store_true',help='Download an already verified ART metadata corpus')
    args=parser.parse_args()
    maven=shutil.which('mvn')
    if not args.adb or not maven or not args.source.is_file():parser.error('adb, Maven and a real source file are required')
    adb=[args.adb]+(['-s',args.serial] if args.serial else [])
    directory='split-legacy-fallback' if args.legacy_fallback_only else 'split-metadata'
    output=ROOT/'target'/directory;output.mkdir(parents=True,exist_ok=True)
    if args.legacy_fallback_only:
        if not args.reuse_desktop:
            run([maven,'-q','-Dtest=SplitMetadataTest#generateLegacyFallback','-Dsplit.legacy.generate=true','-Dsplit.real.file='+str(args.source.resolve()),'-DargLine=-Xmx1536m','test'])
            shutil.copy2(ROOT/'target/surefire-reports/TEST-hbnu.project.ergoutreecrypt.fileops.SplitMetadataTest.xml',output/'desktop-tests.xml')
        elif not (output/'desktop/manifest.properties').is_file():parser.error('No legacy fallback corpus to reuse')
        wrapper=ROOT/'android'/('gradlew.bat' if os.name=='nt' else 'gradlew')
        if not args.skip_build:run([wrapper,':app:assembleDebug',':app:assembleDebugAndroidTest','--console=plain'],cwd=ROOT/'android')
        if not args.resume_android:
            run(adb+['install','-r',ROOT/'android/app/build/outputs/apk/debug/app-debug.apk'])
            run(adb+['install','-r',ROOT/'android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'])
            upload(adb,output/'desktop','files/'+directory+'/desktop')
            result=subprocess.run(adb+['shell','am','instrument','-w','-e','class','hbnu.project.ergoutreecrypt.android.SplitLegacyFallbackTest',PACKAGE+'.test/androidx.test.runner.AndroidJUnitRunner'],capture_output=True,text=True,encoding='utf-8',errors='replace')
            (output/'android-instrumentation.log').write_text(result.stdout+result.stderr,encoding='utf-8');print(result.stdout)
            if result.returncode or 'FAILURES!!!' in result.stdout or 'OK (' not in result.stdout:raise RuntimeError('Legacy fallback ART tests failed')
        download(adb,output/'android','files/'+directory+'/android')
        run([maven,'-q','-Dtest=SplitMetadataTest#verifyLegacyAndroid','-Dsplit.legacy.android=true','-DargLine=-Xmx1536m','test'])
        shutil.copy2(ROOT/'target/surefire-reports/TEST-hbnu.project.ergoutreecrypt.fileops.SplitMetadataTest.xml',output/'android-on-desktop.xml')
        print('PASS: traditional disguise manifest fallback in all eight decrypt/authenticate directions; raw random payloads preserved, missing first/middle/last/all rejected.')
        return
    if not args.reuse_desktop:
        run([maven,'-q','-Dtest=SplitMetadataTest#embeddedBoundaries+generateDesktop,SplitDesktopUiTest',
             '-Dsplit.metadata.generate=true','-Dsplit.metadata.slow='+str(args.slow).lower(),
             '-Dsplit.real.file='+str(args.source.resolve()),'-Dergoutreecrypt.uiTests=true','-DargLine=-Xmx1536m','test'])
        for name,target in [('fileops.SplitMetadataTest','desktop-tests.xml'),('ui.support.SplitDesktopUiTest','desktop-ui.xml')]:
            shutil.copy2(ROOT/('target/surefire-reports/TEST-hbnu.project.ergoutreecrypt.'+name+'.xml'),output/target)
    elif not (output/'desktop/manifest.properties').is_file():parser.error('No metadata corpus to reuse')
    wrapper=ROOT/'android'/('gradlew.bat' if os.name=='nt' else 'gradlew')
    if not args.skip_build:
        run([wrapper,':app:assembleDebug',':app:assembleDebugAndroidTest','--console=plain'],cwd=ROOT/'android')
    if not args.resume_android:
        run(adb+['install','-r',ROOT/'android/app/build/outputs/apk/debug/app-debug.apk'])
        run(adb+['install','-r',ROOT/'android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'])
        upload(adb,output/'desktop','files/split-metadata/desktop')
        tests='hbnu.project.ergoutreecrypt.android.SplitMetadataTest,hbnu.project.ergoutreecrypt.android.SplitDecryptUiTest#embeddedSafSelectionShowsTotalWithoutManifest'
        result=subprocess.run(adb+['shell','am','instrument','-w','-e','class',tests,'-e','splitSlow',str(args.slow).lower(),PACKAGE+'.test/androidx.test.runner.AndroidJUnitRunner'],capture_output=True,text=True,encoding='utf-8',errors='replace')
        (output/'android-instrumentation.log').write_text(result.stdout+result.stderr,encoding='utf-8')
        print(result.stdout)
        if result.returncode or 'FAILURES!!!' in result.stdout or 'OK (' not in result.stdout:raise RuntimeError('ART metadata test failed; see target/split-metadata/android-instrumentation.log')
    download(adb,output/'android','files/split-metadata/android')
    run([maven,'-q','-Dtest=SplitMetadataTest#verifyAndroid','-Dsplit.metadata.android=true','-DargLine=-Xmx1536m','test'])
    shutil.copy2(ROOT/'target/surefire-reports/TEST-hbnu.project.ergoutreecrypt.fileops.SplitMetadataTest.xml',output/'android-on-desktop.xml')
    print('PASS: embedded split metadata in all eight decrypt/authenticate directions; byte and SHA-256 equality, scoped mutations, old formats and both previews checked.')


if __name__=='__main__':main()
