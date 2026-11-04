from pathlib import Path
import re
version=(Path(__file__).resolve().parent.parent/'VERSION').read_text().strip()
if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',version):raise SystemExit('VERSION must be X.Y.Z')
print('tag=v'+version)
