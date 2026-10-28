import fcntl,hashlib,json,os,pathlib,struct,subprocess,tempfile
for prefix in [5,65536]:
 for gap in [8*1024*1024,64*1024*1024]:
  with tempfile.TemporaryDirectory(prefix='ordinary-storage-',dir=os.environ['RUNNER_TEMP']) as work:
   p=pathlib.Path(work)/'payload.bin'
   with p.open('wb') as out:
    out.write(b'a'*prefix);out.seek(gap,os.SEEK_CUR);out.write(b'z'*8)
   before=p.stat()
   with p.open('rb') as src:original=hashlib.file_digest(src,'sha256').hexdigest()
   block=os.statvfs(work).f_bsize;start=128*1024;end=((prefix+gap)//block)*block
   with p.open('r+b') as out:fcntl.fcntl(out.fileno(),99,struct.pack('=IIqq',0,0,start,end-start))
   after=p.stat()
   with p.open('rb') as src:actual=hashlib.file_digest(src,'sha256').hexdigest()
   assert original==actual
   assert after.st_blocks*512<after.st_size//4
   print(json.dumps({'prefix':prefix,'gap':gap,'logical':before.st_size,'allocatedBefore':before.st_blocks*512,'allocatedAfter':after.st_blocks*512,'sha256':actual}),flush=True)
# Gate on the exact production downloader and unchanged regression assertion.
subprocess.run(['python3','-m','unittest','discover','-s','.github/scripts','-p','test_download_sparse_artifact.py','-v'],check=True)
