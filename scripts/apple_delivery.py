"""Validate the existing Apple app, then upload once; never submit for review."""
import base64
import json
import os
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def credentials():
    key_id=os.environ['ASC_KEY_ID']
    issuer=os.environ['ASC_ISSUER_ID']
    if not re.fullmatch(r'[A-Z0-9]{10}',key_id) or not re.fullmatch(r'[a-fA-F0-9-]{36}',issuer):
        raise ValueError('Invalid Apple API identity.')
    raw=base64.b64decode(os.environ['ASC_PRIVATE_KEY_BASE64'],validate=True)
    key=serialization.load_pem_private_key(raw,None)
    if not isinstance(key,ec.EllipticCurvePrivateKey) or not isinstance(key.curve,ec.SECP256R1):
        raise ValueError('Apple ES256 private key required.')
    return key_id,issuer,raw,key

def bearer():
    key_id,issuer,raw,key=credentials()
    encode=lambda value: base64.urlsafe_b64encode(value).rstrip(b'=')
    now=int(time.time())
    header=encode(json.dumps({'alg':'ES256','kid':key_id,'typ':'JWT'}).encode())
    payload=encode(json.dumps({'iss':issuer,'iat':now,'exp':now+600,'aud':'appstoreconnect-v1'}).encode())
    message=header+b'.'+payload
    r,s=decode_dss_signature(key.sign(message,ec.ECDSA(hashes.SHA256())))
    return (message+b'.'+encode(r.to_bytes(32,'big')+s.to_bytes(32,'big'))).decode()

def get(path):
    req=urllib.request.Request('https://api.appstoreconnect.apple.com/v1/'+path,
        headers={'Authorization':'Bearer '+bearer(),'Accept':'application/json'})
    # Do not pass the Apple bearer token to a redirect destination.
    from private_backup import NoRedirect
    with urllib.request.build_opener(NoRedirect()).open(req,timeout=30) as response: return json.load(response)

def validate_target(config):
    identifier=config['app_store_id']
    if str(identifier)!='6820955432' or config['bundle']!='com.baewumnote.beforeempty':
        raise ValueError('Only the existing approved BeforeEmpty Apple app is supported.')
    app=get('apps/'+str(identifier))['data']
    if app.get('id')!=str(identifier) or app['attributes'].get('bundleId')!=config['bundle']:
        raise ValueError('Apple app and bundle do not match.')
    query=urllib.parse.urlencode({'filter[app]':identifier,'filter[version]':config['build'],'limit':'100'})
    if get('builds?'+query)['data']:
        raise ValueError('This build number is already uploaded; inspect processing instead of rebuilding.')

def upload(ipa,config,private,run,environment):
    validate_target(config)
    key_id,issuer,raw,key=credentials()
    key_folder=Path(private)/'apple-upload-keys'
    key_folder.mkdir(mode=0o700)
    key_file=key_folder/('AuthKey_'+key_id+'.p8')
    key_file.write_bytes(raw)
    key_file.chmod(0o600)
    env={**environment,'API_PRIVATE_KEYS_DIR':str(key_folder)}
    arguments=['xcrun','altool','-f',str(ipa),'--type','ios','--apiKey',key_id,'--apiIssuer',issuer,'--output-format','json']
    try:
        run(arguments+['--validate-app'],'apple-package-validation',env=env)
        run(arguments+['--upload-app'],'apple-upload',env=env)
    finally:
        key_file.unlink(missing_ok=True)
