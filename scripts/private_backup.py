"""Encrypted backup only to the existing PRIVATE repository; no public artifacts."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request
import zipfile
from sealed_io import seal

DESTINATION='baewumnote-studio/beforeempty-ios'

def request(path='', payload=None, upload=False):
    token=os.environ.get('PRIVATE_BACKUP_TOKEN','')
    # A broad existing Git Credential Manager/classic token is never accepted.
    if not token.startswith('github_pat_'):
        raise ValueError('A repository-limited fine-grained backup token is required.')
    host='uploads.github.com' if upload else 'api.github.com'
    data=payload if upload else (json.dumps(payload).encode() if payload is not None else None)
    req=urllib.request.Request('https://'+host+'/repos/'+DESTINATION+path,data=data,
        headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json',
                 'X-GitHub-Api-Version':'2022-11-28',
                 'Content-Type':'application/octet-stream' if upload else 'application/json'})
    # Authenticated requests must never follow a redirect to a different host.
    opener=urllib.request.build_opener(NoRedirect())
    with opener.open(req,timeout=180 if upload else 30) as response: return json.load(response)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

def verify_destination():
    repository=request()
    if repository.get('full_name')!=DESTINATION or repository.get('private') is not True:
        raise ValueError('Backup destination must remain private.')
    if repository.get('permissions',{}).get('push') is not True:
        raise ValueError('Private release backup permission unavailable.')

def create_release(mode):
    verify_destination()
    run=os.environ.get('GITHUB_RUN_ID','')
    attempt=os.environ.get('GITHUB_RUN_ATTEMPT','')
    if mode not in ('preflight','ios') or not re.fullmatch(r'[1-9][0-9]*',run) or not re.fullmatch(r'[1-9][0-9]*',attempt):
        raise ValueError('Exact manual run identity required.')
    # A draft release does not publish a tag or alter the existing main branch.
    value=request('/releases',{'tag_name':'beforeempty-store-'+run+'-'+attempt+'-'+mode,
        'target_commitish':'main','name':'BeforeEmpty private build '+run+' / '+mode,
        'body':'Encrypted release binaries or diagnostics. Original source/history retained.',
        'draft':True,'prerelease':True})
    if value.get('draft') is not True or not isinstance(value.get('id'),int):
        raise ValueError('Private draft backup was not created.')
    return value['id']

def store(release_id,kind,folders,key):
    if kind not in ('binaries','diagnostics'): raise ValueError('Unsupported backup kind.')
    verify_destination()
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w',zipfile.ZIP_DEFLATED) as z:
        for folder in folders:
            folder=Path(folder)
            for path in sorted(folder.rglob('*')):
                if path.is_symlink(): raise ValueError('Backup cannot contain symlinks.')
                if path.is_file(): z.write(path,folder.name+'/'+path.relative_to(folder).as_posix())
    raw=seal(data.getvalue(),key)
    asset=request('/releases/'+str(release_id)+'/assets?name=beforeempty-'+kind+'.aesgcm',raw,True)
    digest=hashlib.sha256(raw).hexdigest()
    if asset.get('state')!='uploaded' or asset.get('size')!=len(raw) or asset.get('digest')!='sha256:'+digest:
        raise ValueError('Private backup size/digest verification failed.')
    return {'assetId':asset['id'],'bytes':len(raw),'sha256':digest}
