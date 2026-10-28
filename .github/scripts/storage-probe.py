import hashlib,io,json,os,pathlib,platform,subprocess,tempfile,zipfile
print('platform',platform.platform(),platform.machine(),flush=True)
for location in [os.environ['RUNNER_TEMP'],os.environ['GITHUB_WORKSPACE'],'/private/tmp']:
 with tempfile.TemporaryDirectory(prefix='ordinary-storage-',dir=location) as work:
  root=pathlib.Path(work); p=root/'seek.bin'
  size=64*1024*1024
  with p.open('wb') as f:
   f.write(b'a'*65536); f.seek(size,os.SEEK_CUR); f.write(b'z'*65536)
  info=p.stat()
  print(json.dumps({'location':location,'kind':'seek','logical':info.st_size,'allocated':info.st_blocks*512,'device':info.st_dev,'flags':info.st_flags}),flush=True)
  payload=b'a'*65536+bytes(size)+b'z'*65536
  expected=hashlib.sha256(payload).hexdigest()
  p.unlink()
  archive=root/'payload.zip'
  with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:z.writestr('payload.bin',payload)
  for mode,args,pipe,extra in [
   ('dense-file',['-xf'],False,{}),
   ('sparse-file',['-xSf'],False,{}),
   ('sparse-pipe',['-xSf'],True,{}),
   ('sparse-no-copyfile',['-xSf'],True,{'COPYFILE_DISABLE':'1'}),
   ('sparse-no-metadata',['-xS','--no-mac-metadata','-f'],True,{}),
  ]:
   dest=root/mode;dest.mkdir();env=dict(os.environ,**extra)
   input_file=archive.open('rb') if pipe else None
   try:
    r=subprocess.run(['/usr/bin/tar',*args,'-' if pipe else str(archive),'-C',str(dest)],stdin=input_file,env=env,capture_output=True,text=True)
   finally:
    if input_file:input_file.close()
   out=dest/'payload.bin'
   record={'location':location,'kind':mode,'exit':r.returncode,'stderr':r.stderr[:500]}
   if out.exists():
    info=out.stat();record.update(logical=info.st_size,allocated=info.st_blocks*512,sha256=hashlib.sha256(out.read_bytes()).hexdigest(),device=info.st_dev,flags=info.st_flags)
    assert record['sha256']==expected
    out.unlink()
   print(json.dumps(record),flush=True)
