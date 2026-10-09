"""Original package tool. No token argument, credential printing or provider data."""
import argparse
import hashlib
import json
import shutil
import subprocess
import time
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request,build_opener,HTTPRedirectHandler
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('automatic redirect forbidden')

MECHANISMS={'.gitattributes','.gitignore','README.md','LICENSE','manifest.json','schema.json','upload-policy.json','tools/package.py','examples/synthetic.json'}
MAX_FILE=10*1024*1024
MAX_TOTAL=50*1024*1024

def safe_relative(value):
    if not isinstance(value,str) or not value or value.startswith(('/', '\\')) or '\\' in value or ':' in value:
        raise ValueError('unsafe package path')
    parts=value.split('/')
    reserved={'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]}
    if any(part in ('','.','..') or part.endswith((' ','.')) or part.split('.')[0].upper() in reserved or any(ord(c)<32 for c in part) for part in parts):
        raise ValueError('unsafe package path')
    return parts

def reject_links(path):
    path=Path(path)
    for item in [path,*path.parents]:
        if item.exists():
            stat=item.lstat()
            if item.is_symlink() or getattr(stat,'st_file_attributes',0)&0x400:
                raise ValueError('symlink or reparse point forbidden')

def verify(root):
    root=Path(root).absolute(); reject_links(root)
    manifest=root/'manifest.json'; reject_links(manifest)
    if manifest.stat().st_size>65536: raise ValueError('manifest too large')
    m=json.loads(manifest.read_text())
    if not isinstance(m,dict) or set(m)!={'schema_version','package_id','synthetic','files'} or type(m['schema_version']) is not int or m['schema_version']!=1 or m['synthetic'] is not True:
        raise ValueError('invalid manifest schema')
    safe_relative(m['package_id'])
    if '/' in m['package_id']: raise ValueError('unsafe package id')
    if not isinstance(m['files'],list) or not 1<=len(m['files'])<=1000: raise ValueError('invalid file list')
    seen=set(); total=0
    for f in m['files']:
        if not isinstance(f,dict) or set(f)!={'path','sha256','license'}: raise ValueError('invalid file schema')
        safe_relative(f['path']); alias=f['path'].casefold()
        if alias in seen: raise ValueError('duplicate path alias')
        seen.add(alias)
        if f['path']!='examples/synthetic.json' or f['license']!='synthetic-CC0': raise ValueError('unapproved source or license')
        digest=f['sha256']
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest): raise ValueError('invalid checksum')
        file=root/f['path'];reject_links(file)
        if not file.is_file() or file.stat().st_size>MAX_FILE: raise ValueError('invalid file size')
        total+=file.stat().st_size
        if total>MAX_TOTAL: raise ValueError('package too large')
        with file.open('rb') as stream: actual=hashlib.file_digest(stream,'sha256').hexdigest()
        if actual!=digest: raise ValueError('checksum mismatch')
        data=json.loads(file.read_text())
        if not isinstance(data,dict) or set(data)!={'synthetic','dataset','rows'} or data['synthetic'] is not True or data['dataset']!='daily_bars' or not isinstance(data['rows'],list) or len(data['rows'])!=1:
            raise ValueError('unauthorized payload')
        row=data['rows'][0]
        if not isinstance(row,dict) or any(type(row.get(field)) not in (int,float) for field in ('close','pct_change','amount','volume')): raise ValueError('invalid numeric type')
        if row!={'security_id':'SYNTHETIC.SZ','trade_date':'2026-10-09','close':10.0,'pct_change':1.0,'amount':1000.0,'volume':100.0}:
            raise ValueError('only explicit synthetic fixture approved')
    return m

def import_package(root,destination):
    m=verify(root); destination=Path(destination).absolute();reject_links(destination)
    destination.mkdir(parents=True,exist_ok=True);target=destination/m['package_id'];reject_links(target)
    if target.exists():
        if verify(target)!=m: raise ValueError('package identity collision')
        return target
    stage=target.with_name(target.name+'.staging');reject_links(stage)
    if stage.exists(): raise ValueError('prior staging requires inspection')
    stage.mkdir()
    try:
        for f in m['files']:
            out=stage/f['path'];out.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(Path(root)/f['path'],out)
        shutil.copyfile(Path(root)/'manifest.json',stage/'manifest.json');verify(stage);stage.rename(target)
    except BaseException:
        shutil.rmtree(stage)
        raise
    return target

def download(url,destination,sha256):
    parsed=urlparse(url)
    if parsed.scheme!='https' or parsed.hostname!='raw.githubusercontent.com' or not parsed.path.startswith('/MrLaoGe/x2StockData/') or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port: raise ValueError('untrusted download URL')
    parts=parsed.path.split('/')
    if len(parts)<6 or len(parts[3])!=40 or any(c not in '0123456789abcdef' for c in parts[3]): raise ValueError('exact commit required')
    safe_relative('/'.join(parts[4:]))
    target=Path(destination).absolute();reject_links(target)
    if target.exists(): raise ValueError('do not overwrite existing file')
    stage=target.with_name(target.name+'.part');reject_links(stage); digest=hashlib.sha256()
    try:
        with build_opener(NoRedirect()).open(Request(url,headers={'User-Agent':'x2StockData'}),timeout=30) as response,stage.open('xb') as stream:
            final=urlparse(response.url)
            if final.scheme!='https' or final.hostname not in ('github.com','raw.githubusercontent.com','objects.githubusercontent.com','release-assets.githubusercontent.com'): raise ValueError('untrusted redirect')
            size=0
            while chunk:=response.read(1024*1024):
                size+=len(chunk)
                if size>100*1024*1024: raise ValueError('package too large')
                digest.update(chunk);stream.write(chunk)
        if digest.hexdigest()!=sha256: raise ValueError('download checksum mismatch')
        stage.rename(target)
    finally:
        if stage.exists(): stage.unlink()

def audit_history(root):
    def git(*args):
        return subprocess.run(['git',*args],cwd=root,check=True,capture_output=True).stdout
    head_entries=git('ls-tree','-r','-z','HEAD').split(b'\0')
    approved={}
    for entry in head_entries:
        if not entry: continue
        meta,path=entry.split(b'\t',1);mode,kind,oid=meta.split()
        name=path.decode('utf-8');safe_relative(name)
        if mode!=b'100644' or kind!=b'blob' or name not in MECHANISMS: raise ValueError('unapproved HEAD tree')
        approved[name]=oid
    if set(approved)!=MECHANISMS: raise ValueError('incomplete approved tree')
    commits=git('rev-list','HEAD').decode().splitlines()
    if not commits or len(commits)>1000: raise ValueError('history limit')
    for commit in commits:
        entries={}
        for entry in git('ls-tree','-r','-z',commit).split(b'\0'):
            if not entry: continue
            meta,path=entry.split(b'\t',1);mode,kind,oid=meta.split();name=path.decode('utf-8')
            if mode!=b'100644' or kind!=b'blob' or name not in approved or approved[name]!=oid:
                raise ValueError('unreviewed historical blob; publish clean reviewed root')
            entries[name]=oid
        if entries!=approved: raise ValueError('unreviewed historical tree')
    # Verify exactly the bytes Git will send, never only the working checkout.
    with tempfile.TemporaryDirectory(prefix='x2stock-package-audit-') as temporary:
        target=Path(temporary)
        for name,oid in approved.items():
            content=git('cat-file','blob',oid.decode())
            if len(content)>MAX_FILE: raise ValueError('blob too large')
            file=target/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(content)
        verify(target)
    return git('rev-parse','HEAD').decode().strip()

def upload_once(root,policy):
    m=verify(root)
    if not policy.get('enabled'): return 'disabled'
    if policy.get('repository')!='MrLaoGe/x2StockData': raise ValueError('unexpected repository')
    tracked=set(subprocess.run(['git','ls-files'],cwd=root,check=True,capture_output=True,text=True).stdout.splitlines())
    if tracked!=MECHANISMS: raise ValueError('unexpected tracked assets')
    if subprocess.run(['git','status','--porcelain'],cwd=root,check=True,capture_output=True,text=True).stdout: raise ValueError('dirty repository')
    for file in tracked: reject_links(Path(root)/file)
    remote=subprocess.run(['git','remote','get-url','origin'],cwd=root,check=True,capture_output=True,text=True).stdout.strip()
    if remote not in ('https://github.com/MrLaoGe/x2StockData.git','git@github.com:MrLaoGe/x2StockData.git'): raise ValueError('unexpected origin')
    head=audit_history(root)
    state=Path(root)/'.upload-state.json'
    if state.exists() and json.loads(state.read_text()).get('head')==head: return 'unchanged'
    # Existing Git credential helper handles authentication; never read credentials here.
    subprocess.run(['git','push','origin','HEAD:refs/heads/main'],cwd=root,check=True,capture_output=True)
    state.write_text(json.dumps({'head':head}))
    return 'uploaded'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['verify','import','upload-once','schedule']);parser.add_argument('--root',default='.');parser.add_argument('--destination');args=parser.parse_args()
    if args.action=='verify': verify(args.root);print('verified')
    elif args.action=='import': print(import_package(args.root,args.destination))
    else:
        policy=json.loads((Path(args.root)/'upload-policy.json').read_text())
        if args.action=='upload-once': print(upload_once(args.root,policy))
        else:
            if not policy.get('enabled'): print('disabled');return
            interval=max(3600,int(policy.get('interval_seconds',86400)))
            while True:
                try: upload_once(args.root,policy)
                except Exception: print('upload failed; prior remote package retained')
                time.sleep(interval)
if __name__=='__main__': main()
