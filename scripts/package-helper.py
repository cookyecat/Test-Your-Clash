"""Build the macOS helper from reviewed source; run after npm run build."""
from pathlib import Path
import ast,plistlib,shutil,zipfile
root=Path('.internal/helper-package')
if root.exists():shutil.rmtree(root)
shutil.copytree('helper/package',root)
resources=root/'Install Network Status Helper.app/Contents/Resources'
module=ast.parse(Path('helper/collector.py').read_text())
version=next(ast.literal_eval(n.value) for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VERSION' for t in n.targets))
(resources/'VERSION').write_text(version+'\n')
plist=resources.parent/'Info.plist'
metadata=plistlib.loads(plist.read_bytes())
metadata.update(CFBundleShortVersionString=version,CFBundleVersion=version)
plist.write_bytes(plistlib.dumps(metadata))
shutil.copyfile('helper/collector.py',resources/'collector.py')
shutil.copyfile('.internal/dist/index.html',resources/'index.html')
(root/'Install Network Status Helper.app/Contents/MacOS/install').chmod(0o755)
with zipfile.ZipFile('.internal/Network-Status-Helper-macOS.zip','w',zipfile.ZIP_DEFLATED) as z:
 for p in sorted(root.rglob('*')):
  if p.is_file():z.write(p,p.relative_to(root))
