"""Build and install the URL-handler app locally using macOS's osacompile.
All source is bundled. No downloads, administrator privileges or shell command input.
"""
import datetime, json, os, pathlib, plistlib, shutil, subprocess, sys, tempfile, uuid
BASE=pathlib.Path(__file__).resolve().parent

def build(destination):
    if sys.platform!='darwin':raise RuntimeError('Installer is for macOS only')
    destination=pathlib.Path(destination).expanduser().resolve()
    destination.parent.mkdir(parents=True,exist_ok=True)
    # Prepare the entire new bundle before moving a working installation.
    stage_root=pathlib.Path(tempfile.mkdtemp(prefix='.network-status-build-',dir=destination.parent))
    staged=stage_root/'Network Status Helper.app'
    backup=None
    try:
        subprocess.run(['/usr/bin/osacompile','-o',str(staged),str(BASE/'helper.applescript')],check=True,capture_output=True)
        infofile=staged/'Contents/Info.plist'
        with infofile.open('rb') as f:info=plistlib.load(f)
        info.update(CFBundleIdentifier='local.networkstatus.helper',CFBundleName='Network Status Helper',CFBundleDisplayName='网络状态台助手',CFBundleShortVersionString='4.3.0',CFBundleVersion='430',LSUIElement=True,
            CFBundleURLTypes=[{'CFBundleURLName':'Network Status Local Pairing','CFBundleURLSchemes':['netstatus'],'CFBundleTypeRole':'Viewer'}])
        with infofile.open('wb') as f:plistlib.dump(info,f)
        resources=staged/'Contents/Resources'
        for name in ('launch.py','collector.py','index.html'):
            shutil.copy2(BASE/name,resources/name)
        # Local ad-hoc signing, not Developer ID signing or notarization.
        subprocess.run(['/usr/bin/codesign','--force','--deep','--sign','-',str(staged)],capture_output=True,check=True)
        subprocess.run(['/usr/bin/codesign','--verify','--deep','--strict',str(staged)],capture_output=True,check=True)
        if destination.exists():
            suffix=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'-'+uuid.uuid4().hex[:8]
            backup=destination.with_name(destination.name+'.backup-'+suffix)
            destination.rename(backup)
        try:
            staged.rename(destination)
        except OSError:
            if backup is not None and backup.exists() and not destination.exists():
                backup.rename(destination)
            raise
    finally:
        shutil.rmtree(stage_root,ignore_errors=True)

    return destination

if __name__=='__main__':
    if sys.version_info<(3,9):raise RuntimeError('Python 3.9+ is required')
    test='--build-only' in sys.argv
    dest=(pathlib.Path(sys.argv[2]) if test else pathlib.Path.home()/'Applications/Network Status Helper.app')
    app=build(dest)
    if not test:
        register=pathlib.Path('/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister')
        if register.exists():subprocess.run([str(register),'-f',str(app)],check=False,capture_output=True)
        subprocess.run(['/usr/bin/open',str(app)],check=True)
    print('BUILD_OK')
