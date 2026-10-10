"""Manual sealed build. Public console shows stage results, never private logs."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import traceback
import zipfile
from sealed_io import extract_zip, key_from_env, seal, unseal
import private_backup
import apple_delivery

REPO=Path(__file__).resolve().parents[1]
MODE=sys.argv[1] if len(sys.argv)==2 else ''
STAGE='initialization'

def run(command, label, cwd=None, env=None):
    global STAGE
    STAGE=label
    with (LOGS/(label+'.log')).open('ab') as log:
        result=subprocess.run(command,cwd=cwd or APP,env=env or ENV,stdout=log,stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError('Private diagnostic is encrypted.')
    print('PASS: '+label,flush=True)

def configure_environment():
    config=json.loads((APP/'release/production_config.json').read_text())
    env=dict(os.environ)
    env.update(RELEASE_CONFIG='1',ADMOB_APP_ID=config['admob_app_id'],BUNDLE_ID=config['bundle'],
               APPLE_TEAM_ID=config['team'],CI='true',FLUTTER_SUPPRESS_ANALYTICS='true')
    # Dependency downloads/Flutter/CocoaPods never inherit signing, decryption,
    # Apple upload or private-repository backup credentials.
    for name in SECRET_NAMES: env.pop(name,None)
    return env,config

SECRET_NAMES=('BUILD_INPUT_KEY','IOS_DISTRIBUTION_P12_BASE64','IOS_DISTRIBUTION_P12_PASSWORD',
              'IOS_APPSTORE_PROFILE_BASE64','ASC_KEY_ID','ASC_ISSUER_ID','ASC_PRIVATE_KEY_BASE64',
              'PRIVATE_BACKUP_TOKEN','GITHUB_TOKEN','GH_TOKEN')

def signing_env():
    return {**ENV,**{name:os.environ[name] for name in SECRET_NAMES[1:4]}}

def flutter_arguments():
    return ['--release','--build-number='+CONFIG['build'],
            '--dart-define=ADMOB_USE_TEST_ADS=false',
            '--dart-define=SCREENSHOT_MODE=false',
            '--dart-define=ADMOB_INTERSTITIAL_ID='+CONFIG['admob_interstitial_id'],
            '--dart-define=SUPPORT_URL='+CONFIG['support_url'],
            '--dart-define=PRIVACY_POLICY_URL='+CONFIG['privacy_url']]

def setup_flutter():
    target=PRIVATE/'flutter'
    run(['git','clone','--depth','1','--branch','3.47.5','https://github.com/flutter/flutter.git',str(target)],'install-flutter',REPO)
    actual=subprocess.run(['git','rev-parse','HEAD'],cwd=target,env=ENV,capture_output=True,text=True,check=True).stdout.strip()
    if actual!=MANIFEST['flutter_commit']: raise ValueError('Flutter tag moved since version verification.')
    ENV['PATH']=str(target/'bin')+os.pathsep+ENV['PATH']
    run(['flutter','--version'],'flutter-version')
    run(['flutter','pub','get','--enforce-lockfile'],'dependencies')

def preflight():
    global STAGE
    STAGE='private-backup-access'
    private_backup.verify_destination()
    run([sys.executable,'release/check_source.py'],'reviewed-source')
    run([sys.executable,'-m','unittest','discover','-s','release','-p','test_*.py'],'signing-guard-tests')
    run([sys.executable,'release/appstore_signing.py','preflight'],'real-appstore-signing',env=signing_env())
    if DELIVER:
        STAGE='existing-apple-app-and-build-number'
        apple_delivery.validate_target(CONFIG)
        print('PASS: existing-apple-app-and-build-number',flush=True)
    setup_flutter()
    run(['flutter','analyze','--no-pub'],'app-analysis')
    run(['flutter','test','--no-pub','--dart-define=ADMOB_USE_TEST_ADS=true'],'app-tests')

def select_xcode():
    global STAGE
    STAGE='select-xcode'
    candidates=sorted(Path('/Applications').glob('Xcode*.app/Contents/Developer'))
    for candidate in candidates:
        trial={**ENV,'DEVELOPER_DIR':str(candidate)}
        version=subprocess.run(['xcodebuild','-version'],env=trial,capture_output=True,text=True,check=True).stdout
        if version.splitlines()[0]=='Xcode 26.6':
            ENV['DEVELOPER_DIR']=str(candidate); break
    else: raise RuntimeError('Required verified Xcode unavailable.')

def build_ios():
    global PROFILE_UUID,KEYCHAIN,STAGE
    select_xcode()
    run([sys.executable,'release/check_source.py'],'reviewed-source')
    run([sys.executable,'release/appstore_signing.py','preflight'],'real-appstore-signing',env=signing_env())
    setup_flutter()
    run([sys.executable,'tool/configure_ios.py'],'production-ios-configuration')
    run(['flutter','build','ios','--no-codesign',*flutter_arguments()],'unsigned-release-compile')
    if not DELIVER: return
    sys.path.insert(0,str(APP/'release'))
    import appstore_signing as signing
    profile=signing.shared.decode_profile(base64.b64decode(os.environ['IOS_APPSTORE_PROFILE_BASE64'],validate=True))
    signing.validate_profile(profile)
    PROFILE_UUID=profile['UUID']
    run([sys.executable,'release/appstore_signing.py','install'],'install-appstore-profile',env=signing_env())
    options=plistlib.loads((TEMP/'beforeempty-export-options.plist').read_bytes())
    PROFILE_UUID=options['provisioningProfiles'][CONFIG['bundle']]
    KEYCHAIN=TEMP/'beforeempty-signing.keychain-db'
    keychain_password=secrets.token_hex(24)
    for command,label in [
        (['security','create-keychain','-p',keychain_password,str(KEYCHAIN)],'create-temporary-keychain'),
        (['security','set-keychain-settings','-lut','21600',str(KEYCHAIN)],'keychain-expiry'),
        (['security','unlock-keychain','-p',keychain_password,str(KEYCHAIN)],'unlock-signing'),
        (['security','import',str(TEMP/'beforeempty-distribution.p12'),'-P',os.environ['IOS_DISTRIBUTION_P12_PASSWORD'],'-T','/usr/bin/codesign','-t','cert','-f','pkcs12','-k',str(KEYCHAIN)],'import-existing-identity'),
        (['security','set-key-partition-list','-S','apple-tool:,apple:','-k',keychain_password,str(KEYCHAIN)],'signing-partition'),
        (['security','list-keychains','-d','user','-s',str(KEYCHAIN),str(Path.home()/'Library/Keychains/login.keychain-db')],'signing-keychain-list'),
        (['security','default-keychain','-d','user','-s',str(KEYCHAIN)],'select-signing-keychain')]:
        run(command,label)
    run([sys.executable,'release/appstore_signing.py','settings'],'resolved-signing-settings',env=signing_env())
    run(['flutter','build','ipa','--export-options-plist='+str(TEMP/'beforeempty-export-options.plist'),*flutter_arguments()],'signed-appstore-build')
    run([sys.executable,'release/appstore_signing.py','archive'],'actual-native-archive-signature',env=signing_env())
    # Validate the exported IPA's actual app and embedded Store profile as well.
    ipas=list((APP/'build/ios/ipa').glob('*.ipa'))
    if len(ipas)!=1: raise ValueError('One exported IPA required.')
    with zipfile.ZipFile(ipas[0]) as z:
        bad=z.testzip()
        infos=[n for n in z.namelist() if n.startswith('Payload/') and n.count('/')==2 and n.endswith('.app/Info.plist')]
        if bad or len(infos)!=1: raise ValueError('Invalid IPA layout or CRC.')
        signing.validate_info(plistlib.loads(z.read(infos[0])))
        signing.validate_profile(signing.shared.decode_profile(z.read(infos[0].replace('Info.plist','embedded.mobileprovision'))))
    exported=PRIVATE/'exported'
    run(['ditto','-x','-k',str(ipas[0]),str(exported)],'read-exported-app')
    apps=list((exported/'Payload').glob('*.app'))
    if len(apps)!=1: raise ValueError('One exported app required.')
    run(['codesign','--verify','--deep','--strict',str(apps[0])],'exported-native-signature')
    # Extract-certificate output uses cwd; run explicitly in the temporary folder.
    (TEMP/'codesign0').unlink(missing_ok=True)
    result=subprocess.run(['codesign','-d','--extract-certificates',str(apps[0])],cwd=TEMP,env=ENV,capture_output=True,check=True)
    if hashlib.sha256((TEMP/'codesign0').read_bytes()).hexdigest()!=signing.shared.CERT_SHA:
        raise ValueError('Exported signer differs.')
    shutil.copy2(ipas[0],OUTPUT/'beforeempty-1.0.0-2.ipa')
    archives=list((APP/'build/ios/archive').glob('*.xcarchive'))
    if len(archives)!=1: raise ValueError('One original archive required.')
    with tarfile.open(OUTPUT/'beforeempty-1.0.0-2.xcarchive.tar.gz','w:gz') as tar:
        tar.add(archives[0],arcname=archives[0].name)
    retain_and_upload(ipas[0])


def capture_screenshots():
    global SIMULATOR_UUID,STAGE,BACKUP_ID
    if DELIVER: raise ValueError('Screenshot capture cannot upload a device app.')
    chosen_locale=os.environ.get('SCREENSHOT_LOCALE','all')
    chosen_scene=os.environ.get('SCREENSHOT_SCENE','all')
    if chosen_locale not in ('all','en','ko') or chosen_scene not in ('all','home','detail','history'):
        raise ValueError('Unknown capture selection.')
    private_backup.verify_destination()
    select_xcode()
    run([sys.executable,'release/check_source.py'],'reviewed-source')
    setup_flutter()
    run([sys.executable,'tool/configure_ios.py'],'screenshot-ios-configuration')
    # Use an installed medium Dynamic Island device at its native pixel size.
    devices=json.loads(subprocess.run(['xcrun','simctl','list','devices','available','--json'],
        env=ENV,capture_output=True,text=True,check=True).stdout)['devices']
    candidates=[(runtime,device) for runtime,group in devices.items() if '.iOS-' in runtime
        for device in group if device.get('isAvailable') and device['name'] in ('iPhone 17 Pro','iPhone 16 Pro','iPhone 15 Pro')]
    if not candidates: raise ValueError('Supported installed iPhone Simulator unavailable.')
    runtime,device=sorted(candidates,key=lambda item:(item[1]['name'],item[0]),reverse=True)[0]
    device_type=device['deviceTypeIdentifier']
    SIMULATOR_UUID=subprocess.run(['xcrun','simctl','create','BeforeEmptyScreenshots',device_type,runtime],
        env=ENV,capture_output=True,text=True,check=True).stdout.strip()
    run(['xcrun','simctl','boot',SIMULATOR_UUID],'boot-screenshot-device')
    run(['xcrun','simctl','bootstatus',SIMULATOR_UUID,'-b'],'wait-for-screenshot-device')
    run(['xcrun','simctl','status_bar',SIMULATOR_UUID,'override','--time','9:41','--dataNetwork','wifi',
        '--wifiMode','active','--wifiBars','3','--batteryState','charged','--batteryLevel','100'],'screenshot-status-bar')
    index=[]
    for locale in ('en','ko'):
        if chosen_locale not in ('all',locale): continue
        for position,scene in enumerate(('home','detail','history'),1):
            if chosen_scene not in ('all',scene): continue
            label=locale+'-'+scene
            run(['flutter','build','ios','--simulator','--debug','--no-pub','--no-codesign',
                '--dart-define=SCREENSHOT_MODE=true','--dart-define=SCREENSHOT_LOCALE='+locale,
                '--dart-define=SCREENSHOT_SCENE='+scene,'--dart-define=SCREENSHOT_THEME=light',
                '--dart-define=ADMOB_USE_TEST_ADS=true'],'simulator-compile-'+label)
            app=APP/'build/ios/iphonesimulator/Runner.app'
            if not app.is_dir(): raise ValueError('Compiled native Simulator app missing.')
            if index:
                run(['xcrun','simctl','terminate',SIMULATOR_UUID,CONFIG['bundle']],'terminate-'+label)
            run(['xcrun','simctl','install',SIMULATOR_UUID,str(app)],'install-'+label)
            run(['xcrun','simctl','launch',SIMULATOR_UUID,CONFIG['bundle']],'launch-'+label)
            # Wait for rendered content rather than retaining a loading frame.
            time.sleep(8)
            raw=PRIVATE/(label+'.png')
            folder=OUTPUT/'screenshots'/locale
            folder.mkdir(parents=True,exist_ok=True)
            target=folder/(str(position).zfill(2)+'-'+scene+'.jpg')
            checker=PRIVATE/'check-rendered-image.swift'
            checker.write_text('''import AppKit
import Foundation
guard let image = NSBitmapImageRep(contentsOfFile: CommandLine.arguments[1]) else { exit(2) }
var dark = 0
var total = 0
for y in stride(from: Int(Double(image.pixelsHigh)*0.20), to: Int(Double(image.pixelsHigh)*0.95), by: 12) {
    for x in stride(from: Int(Double(image.pixelsWide)*0.04), to: Int(Double(image.pixelsWide)*0.96), by: 12) {
        guard let color = image.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else { exit(2) }
        total += 1
        if max(color.redComponent, max(color.greenComponent, color.blueComponent)) < 0.70 { dark += 1 }
    }
}
exit(total > 0 && Double(dark)/Double(total) > 0.003 ? 0 : 1)
''')
            for attempt in range(12):
                run(['xcrun','simctl','io',SIMULATOR_UUID,'screenshot',str(raw)],'capture-'+label)
                check=subprocess.run(['swift',str(checker),str(raw)],env=ENV,capture_output=True)
                if check.returncode == 0: break
                if check.returncode != 1: raise ValueError('Native rendered-image check failed.')
                time.sleep(5)
            else: raise ValueError('Native screen remained blank or loading.')
            run(['sips','-s','format','jpeg','-s','formatOptions','100',str(raw),'--out',str(target)],'opaque-native-image-'+label)
            dimensions=subprocess.run(['sips','-g','pixelWidth','-g','pixelHeight',str(target)],
                env=ENV,capture_output=True,text=True,check=True).stdout
            size=tuple(int(line.split(':',1)[1].strip()) for line in dimensions.splitlines() if 'pixelWidth:' in line or 'pixelHeight:' in line)
            if size not in ((1179,2556),(1206,2622)): raise ValueError('Screenshot must have accepted native medium-display dimensions.')
            index.append({'locale':locale,'scene':scene,'file':target.relative_to(OUTPUT).as_posix(),
                'size':size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'nativeSimulator':True})
    (OUTPUT/'screenshots/capture-index.json').write_text(json.dumps({'deviceName':device['name'],
        'runtime':runtime,'sourceSha256':MANIFEST['source_sha256'],'screenshots':index},indent=2))
    STAGE='private-screenshot-backup'
    BACKUP_ID=private_backup.create_release(MODE)
    private_backup.store(BACKUP_ID,'binaries',[OUTPUT],KEY)
    print('PASS: native-localized-screenshots-retained-privately',flush=True)

def retain_and_upload(ipa):
    global STAGE,BACKUP_ID
    STAGE='private-binary-backup'
    BACKUP_ID=private_backup.create_release(MODE)
    receipt=private_backup.store(BACKUP_ID,'binaries',[OUTPUT],KEY)
    (LOGS/'private-backup-receipt.json').write_text(json.dumps(receipt))
    print('PASS: signed-app-and-original-archive-retained-privately',flush=True)
    # Upload only after both native signature verification and private backup.
    apple_delivery.upload(ipa,CONFIG,PRIVATE,run,ENV)

def cleanup():
    if SIMULATOR_UUID:
        subprocess.run(['xcrun','simctl','shutdown',SIMULATOR_UUID],env=ENV,capture_output=True)
        subprocess.run(['xcrun','simctl','delete',SIMULATOR_UUID],env=ENV,capture_output=True)
    if KEYCHAIN and KEYCHAIN.exists():
        subprocess.run(['security','default-keychain','-d','user','-s',str(Path.home()/'Library/Keychains/login.keychain-db')],capture_output=True)
        subprocess.run(['security','delete-keychain',str(KEYCHAIN)],capture_output=True)
    if PROFILE_UUID:
        (Path.home()/'Library/MobileDevice/Provisioning Profiles'/(PROFILE_UUID+'.mobileprovision')).unlink(missing_ok=True)
    for name in ['beforeempty-distribution.p12','beforeempty-runner.mobileprovision','beforeempty-export-options.plist']:
        (TEMP/name).unlink(missing_ok=True)
    for path in TEMP.glob('codesign[0-9]*'):
        if path.is_file(): path.unlink()
    if PRIVATE.is_relative_to(TEMP) and PRIVATE.name=='beforeempty-private-build':
        shutil.rmtree(PRIVATE)

def main():
    global TEMP,PRIVATE,APP,LOGS,OUTPUT,ENV,CONFIG,PROFILE_UUID,KEYCHAIN,SIMULATOR_UUID,MANIFEST,KEY,BACKUP_ID,DELIVER,STAGE
    if (MODE not in ('preflight','ios','screenshots') or os.environ.get('GITHUB_ACTIONS')!='true'
            or os.environ.get('GITHUB_REPOSITORY')!='baewumnote-studio/beforeempty-ios-public-build'
            or os.environ.get('GITHUB_REF')!='refs/heads/main'
            or os.environ.get('GITHUB_EVENT_NAME')!='workflow_dispatch'
            or os.environ.get('REPOSITORY_IS_PUBLIC')!='true'):
        raise ValueError('Manual main-branch PUBLIC runner required.')
    KEY=key_from_env()
    DELIVER=os.environ.get('UPLOAD_APP')=='true'
    MANIFEST=json.loads((REPO/'build-manifest.json').read_text())
    source=(REPO/'app-source.aesgcm').read_bytes()
    if hashlib.sha256(source).hexdigest()!=MANIFEST['source_sha256']:
        raise ValueError('Reviewed encrypted source digest differs.')
    TEMP=Path(os.environ['RUNNER_TEMP']).resolve()
    PRIVATE=TEMP/'beforeempty-private-build'
    if PRIVATE.exists(): raise ValueError('Private workspace must start empty.')
    APP=PRIVATE/'app'; LOGS=PRIVATE/'diagnostics'; OUTPUT=PRIVATE/'output'
    LOGS.mkdir(parents=True); OUTPUT.mkdir()
    PROFILE_UUID=None; KEYCHAIN=None; SIMULATOR_UUID=None; BACKUP_ID=None; success=False
    try:
        extract_zip(unseal(source,KEY),PRIVATE)
        ENV,CONFIG=configure_environment()
        {'preflight':preflight,'ios':build_ios,'screenshots':capture_screenshots}[MODE]()
        success=True
    except Exception:
        (LOGS/'failure.txt').write_text(traceback.format_exc())
        print('FAIL: '+STAGE+'; private diagnostics contain the cause.',flush=True)
    finally:
        try:
            (LOGS/'result.json').write_text(json.dumps({'mode':MODE,'success':success,'lastStage':STAGE,
                'appleUpload':success and DELIVER and MODE=='ios','reviewSubmission':False,
                'sourceSha256':MANIFEST['source_sha256']}))
            try:
                if BACKUP_ID is None: BACKUP_ID=private_backup.create_release(MODE)
                private_backup.store(BACKUP_ID,'diagnostics',[LOGS],KEY)
                print('PASS: diagnostics-retained-privately',flush=True)
            except Exception:
                print('FAIL: private-diagnostic-backup',flush=True)
                success=False
        finally:
            cleanup()
    return 0 if success else 1

if __name__=='__main__':
    try: sys.exit(main())
    except Exception:
        print('FAIL: sealed build initialization. No private details printed.',flush=True)
        sys.exit(1)
