"""Exercise actual confidentiality and delivery failure paths with synthetic inputs."""
import base64
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
import apple_delivery
import private_backup
import run_build
from sealed_io import unseal

CONFIG={'app_store_id':'6820955432','bundle':'com.baewumnote.beforeempty','build':'2',
        'admob_app_id':'public-fixture','team':'TEAMFIXTUR'}

class ReleaseSecurityTests(unittest.TestCase):
    def test_screenshot_mode_refuses_apple_upload_before_accessing_credentials(self):
        with patch.object(run_build,'DELIVER',True,create=True),patch.object(private_backup,'verify_destination') as destination,patch.object(run_build,'select_xcode') as xcode:
            with self.assertRaises(ValueError): run_build.capture_screenshots()
            destination.assert_not_called()
            xcode.assert_not_called()

    def test_dependencies_do_not_receive_signing_decryption_or_upload_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            app=Path(temp); (app/'release').mkdir()
            (app/'release/production_config.json').write_text(json.dumps(CONFIG))
            fixture={name:'synthetic-value' for name in run_build.SECRET_NAMES}
            with patch.dict(os.environ,fixture),patch.object(run_build,'APP',app,create=True):
                environment,config=run_build.configure_environment()
                self.assertTrue(all(name not in environment for name in run_build.SECRET_NAMES))
                with patch.object(run_build,'ENV',environment,create=True):
                    signed=run_build.signing_env()
                    self.assertTrue(all(signed[name]=='synthetic-value' for name in run_build.SECRET_NAMES[1:4]))
                    for name in ['BUILD_INPUT_KEY','ASC_PRIVATE_KEY_BASE64','PRIVATE_BACKUP_TOKEN']:
                        self.assertNotIn(name,signed)

    def test_private_repository_and_pr_runs_fail_before_decrypting(self):
        base={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'baewumnote-studio/beforeempty-ios-public-build',
              'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch','REPOSITORY_IS_PUBLIC':'true'}
        for name,value in [('REPOSITORY_IS_PUBLIC','false'),('GITHUB_EVENT_NAME','pull_request'),
                           ('GITHUB_REF','refs/heads/other'),('GITHUB_REPOSITORY','someone/fork')]:
            with patch.dict(os.environ,{**base,name:value}),patch.object(run_build,'MODE','ios'),patch.object(run_build,'key_from_env') as key:
                with self.assertRaises(ValueError): run_build.main()
                key.assert_not_called()

    def test_existing_github_classic_credential_cannot_be_used_for_backup(self):
        with patch.dict(os.environ,{'PRIVATE_BACKUP_TOKEN':'ghp_'+('x'*40)}):
            with self.assertRaises(ValueError): private_backup.request()

    def test_backup_refuses_a_public_repository(self):
        with patch.object(private_backup,'request',return_value={'full_name':private_backup.DESTINATION,'private':False,'permissions':{'push':True}}):
            with self.assertRaises(ValueError): private_backup.verify_destination()

    def test_backup_upload_is_authenticated_ciphertext_and_checks_digest(self):
        key=os.urandom(32)
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/'output'; folder.mkdir(); (folder/'fixture.ipa').write_bytes(b'private signed fixture')
            for valid in [False,True]:
                def endpoint(path='',payload=None,upload=False):
                    if not upload: return {'full_name':private_backup.DESTINATION,'private':True,'permissions':{'push':True}}
                    self.assertNotIn(b'private signed fixture',payload)
                    decoded=unseal(payload,key)
                    with zipfile.ZipFile(io.BytesIO(decoded)) as z:
                        self.assertEqual(z.read('output/fixture.ipa'),b'private signed fixture')
                    import hashlib
                    return {'id':123,'state':'uploaded','size':len(payload),'digest':'sha256:'+(hashlib.sha256(payload).hexdigest() if valid else 'wrong')}
                with patch.object(private_backup,'request',side_effect=endpoint):
                    if valid: self.assertEqual(private_backup.store(1,'binaries',[folder],key)['assetId'],123)
                    else:
                        with self.assertRaises(ValueError): private_backup.store(1,'binaries',[folder],key)

    def test_apple_upload_never_runs_if_private_binary_backup_fails(self):
        with patch.object(run_build,'MODE','ios'),patch.object(run_build,'OUTPUT',Path('synthetic-output'),create=True),patch.object(run_build,'KEY',b'x'*32,create=True),patch.object(private_backup,'create_release',return_value=1),patch.object(private_backup,'store',side_effect=ValueError('fixture backup failure')),patch.object(apple_delivery,'upload') as upload:
            with self.assertRaises(ValueError): run_build.retain_and_upload(Path('fixture.ipa'))
            upload.assert_not_called()

    def test_wrong_apple_bundle_or_used_build_is_rejected(self):
        for bundle,builds in [('com.other.app',[]),(CONFIG['bundle'],[{'id':'existing'}])]:
            with patch.object(apple_delivery,'get',side_effect=[{'data':{'id':CONFIG['app_store_id'],'attributes':{'bundleId':bundle}}},{'data':builds}]):
                with self.assertRaises(ValueError): apple_delivery.validate_target(CONFIG)
        with patch.object(apple_delivery,'get',side_effect=[{'data':{'id':CONFIG['app_store_id'],'attributes':{'bundleId':CONFIG['bundle']}}},{'data':[]}]):
            apple_delivery.validate_target(CONFIG)

    def test_apple_bearer_is_short_lived_and_cryptographically_valid(self):
        key=ec.generate_private_key(ec.SECP256R1())
        raw=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
        environment={'ASC_KEY_ID':'TESTKEY123','ASC_ISSUER_ID':'12345678-1234-1234-1234-123456789abc','ASC_PRIVATE_KEY_BASE64':base64.b64encode(raw).decode()}
        with patch.dict(os.environ,environment): token=apple_delivery.bearer()
        header,payload,signature=token.split('.')
        decode=lambda value:base64.urlsafe_b64decode(value+'='*(-len(value)%4))
        data=json.loads(decode(payload))
        self.assertEqual(data['exp']-data['iat'],600)
        self.assertEqual(data['aud'],'appstoreconnect-v1')
        signed=decode(signature)
        key.public_key().verify(encode_dss_signature(int.from_bytes(signed[:32],'big'),int.from_bytes(signed[32:],'big')),(header+'.'+payload).encode(),ec.ECDSA(hashes.SHA256()))

    def test_apple_key_is_removed_even_when_package_validation_fails(self):
        def reject(*args,**kwargs): raise RuntimeError('synthetic validation failure')
        with tempfile.TemporaryDirectory() as temp,patch.object(apple_delivery,'validate_target'),patch.object(apple_delivery,'credentials',return_value=('TESTKEY123','fixture-issuer',b'fixture-not-a-real-key',None)):
            with self.assertRaises(RuntimeError): apple_delivery.upload(Path('fixture.ipa'),CONFIG,Path(temp),reject,{})
            self.assertFalse(list(Path(temp).rglob('*.p8')))

if __name__=='__main__': unittest.main()
