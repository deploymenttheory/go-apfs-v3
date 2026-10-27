import io,json,os,subprocess,urllib.request,urllib.error,zipfile,hashlib,shutil
from pathlib import Path
base=Path(os.environ['APFS_NATIVE_WORK']);base.mkdir(parents=True,exist_ok=True)
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
token=os.environ['GH_TOKEN']
req=urllib.request.Request('https://api.github.com/repos/deploymenttheory/go-apfs-v3/actions/artifacts/12737801363/zip',headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json'})
try:
 urllib.request.build_opener(NoRedirect).open(req)
 raise RuntimeError('Expected artifact redirect')
except urllib.error.HTTPError as e:
 if e.code not in [301,302,303,307,308]:raise
 url=e.headers['Location']
del token,req
assert url.startswith('https://')
size=4400337887
class Ranges(io.RawIOBase):
 def __init__(self):self.pos=0;self.start=0;self.cache=b'';self.transferred=0
 def seekable(self):return True
 def readable(self):return True
 def tell(self):return self.pos
 def seek(self,o,w=0):self.pos=o if w==0 else self.pos+o if w==1 else size+o;return self.pos
 def read(self,n=-1):
  n=size-self.pos if n<0 else min(n,size-self.pos)
  if n>256<<20:raise RuntimeError('Refusing whole archive')
  out=[]
  while n>0:
   if not self.start<=self.pos<self.start+len(self.cache):
    self.start=self.pos;end=min(size-1,self.start+(4<<20)-1)
    request=urllib.request.Request(url,headers={'Range':f'bytes={self.start}-{end}','Accept-Encoding':'identity'})
    with urllib.request.urlopen(request,timeout=90) as r:
     if r.status!=206:raise RuntimeError('Byte ranges unsupported')
     self.cache=r.read()
    assert len(self.cache)==end-self.start+1
    self.transferred+=len(self.cache)
   at=self.pos-self.start;count=min(n,len(self.cache)-at)
   out.append(self.cache[at:at+count]);self.pos+=count;n-=count
  return b''.join(out)
stream=Ranges();target='macos-27.encrypted-snapshot-history.apfs.decrypted.convert-volume.UDZO.dmg'
with zipfile.ZipFile(stream) as z:
 manifest_name=next(n for n in z.namelist() if n=='outputs.json' or n.endswith('/outputs.json'))
 raw=z.read(manifest_name);manifest=json.loads(raw)
 entry=next(x for x in manifest['outputs'] if x['file']==target)
 name=next(n for n in z.namelist() if n==target or n.endswith('/'+target))
 dest=base/'ci-reencryption-linux-macos27-original.dmg'
 with z.open(name) as source,dest.open('wb') as output:shutil.copyfileobj(source,output,1<<20)
 (base/'ci-reencryption-linux-macos27-outputs-original.json').write_bytes(raw)
 digest=hashlib.sha256(dest.read_bytes()).hexdigest()
 assert digest==entry['sha256'] and dest.stat().st_size==entry['bytes']
receipt={'artifact':12737801363,'originalArchiveBytes':size,'fullArchiveDigestVerified':False,'projection':'Original manifest and named image extracted through ZIP byte ranges; entry CRC and image SHA256/size verified against original manifest. No original entry bytes or names changed.','entry':name,'sha256':digest,'bytes':dest.stat().st_size,'rangeBytesTransferred':stream.transferred}
(base/'ci-reencryption-original-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
