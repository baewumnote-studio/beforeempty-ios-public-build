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

def build_ios():
    global PROFILE_UUID,KEYCHAIN,STAGE
    STAGE='select-xcode'
    candidates=sorted(Path('/Applications').glob('Xcode*.app/Contents/Developer'))
    for candidate in candidates:
        trial={**ENV,'DEVELOPER_DIR':str(candidate)}
        version=subprocess.run(['xcodebuild','-version'],env=trial,capture_output=True,text=True,check=True).stdout
        if version.splitlines()[0]=='Xcode 26.6':
            ENV['DEVELOPER_DIR']=str(candidate); break
    else: raise RuntimeError('Required verified Xcode unavailable.')
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
    global TEMP,PRIVATE,APP,LOGS,OUTPUT,ENV,CONFIG,PROFILE_UUID,KEYCHAIN,MANIFEST,KEY,BACKUP_ID,DELIVER,STAGE
    if (MODE not in ('preflight','ios') or os.environ.get('GITHUB_ACTIONS')!='true'
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
    PROFILE_UUID=None; KEYCHAIN=None; BACKUP_ID=None; success=False
    try:
        extract_zip(unseal(source,KEY),PRIVATE)
        ENV,CONFIG=configure_environment()
        (preflight if MODE=='preflight' else build_ios)()
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
