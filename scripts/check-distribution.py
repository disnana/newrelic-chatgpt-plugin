from pathlib import Path
import re,json,sys
root=Path(__file__).resolve().parent.parent
rules=[r'appgprj_[A-Za-z0-9]+',r'plugin_asdk_app_sites_[A-Za-z0-9]+',r'NRAK-[A-Za-z0-9_-]{16,}',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)',r'localhost:\d+/callback\?[^\s]*state=[A-Za-z0-9_-]{16,}']
errors=[]
for p in root.rglob('*'):
 if not p.is_file() or any(x in p.relative_to(root).parts for x in ['.git','dist','outputs','node_modules','__pycache__']):continue
 if p.is_symlink():errors.append(str(p)+': symlink');continue
 if p.name.startswith('.env') and p.name!='.env.example':errors.append(str(p)+': environment file');continue
 text=p.read_text(encoding='utf-8')
 if any(re.search(rule,text) for rule in rules): errors.append(str(p.relative_to(root))+': potential private data')
manifest=json.loads((root/'.openai/hosting.json').read_text())
if 'project_id' in manifest:errors.append('portable manifest has project_id')
if errors:raise SystemExit('\n'.join(errors))
print('Portable source identifiers and secret-pattern checks passed (not a complete secret detector)')
