from pathlib import Path
from zipfile import ZipFile,ZIP_DEFLATED,ZipInfo
import hashlib,re,subprocess,sys
root=Path(__file__).resolve().parent.parent
version=sys.argv[1] if len(sys.argv)>1 else 'v'+(root/'VERSION').read_text().strip()
if not re.fullmatch(r'v\d+\.\d+\.\d+',version):raise SystemExit('Expected vX.Y.Z')
subprocess.run([sys.executable,str(root/'scripts/check-distribution.py')],check=True)
files=[p for p in root.rglob('*') if p.is_file() and not any(x in p.relative_to(root).parts for x in ['.git','dist','outputs','node_modules','__pycache__'])]
required=['VERSION','README.md','README.en.md','LICENSE','package.json','.openai/hosting.json','worker/index.js','worker/newrelic.js','drizzle/0000_newrelic_mcp.sql','drizzle/0001_refresh_locks.sql','docs/setup.md','docs/oauth.md','docs/troubleshooting.md']
assert all((root/p).is_file() for p in required)
out=root/'outputs';out.mkdir(exist_ok=True)
archive=out/f'NewRelic-ChatGPT-setup-{version}.zip'
with ZipFile(archive,'w',ZIP_DEFLATED) as z:
 for p in sorted(files):
  info=ZipInfo('NewRelic-ChatGPT-setup/'+p.relative_to(root).as_posix(),(2026,1,1,0,0,0));info.compress_type=ZIP_DEFLATED
  z.writestr(info,p.read_bytes())
with ZipFile(archive) as z:
 assert z.testzip() is None
 assert len(z.namelist())==len(files)
 assert all(not name.startswith('/') and '..' not in name.split('/') for name in z.namelist())
 for p in required:assert 'NewRelic-ChatGPT-setup/'+p in z.namelist()
checksum=hashlib.sha256(archive.read_bytes()).hexdigest()
(out/'checksums.txt').write_text(checksum+'  '+archive.name+'\n')
print(archive)
