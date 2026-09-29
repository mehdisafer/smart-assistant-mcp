"""Version-bound local stdio launcher. Never imports or starts a Remote Device client."""
from __future__ import annotations
import hashlib,json,os,subprocess,sys
from pathlib import Path
from .runner import WindowsJob
from .common import atomic_json

SAFE_ENV={'SYSTEMROOT','WINDIR','PATH','COMSPEC','PATHEXT','APPDATA','LOCALAPPDATA'}
BLOCKED=['format','diskpart','shutdown','reboot','runas','takeown']

def main():
    # Trusted launch configuration, not end-user tool arguments.
    if len(sys.argv)!=4:raise SystemExit('COMPAT_LAUNCH_CONFIGURATION_REQUIRED')
    profile_root,node,entry=map(Path,sys.argv[1:4])
    if not all(p.is_absolute() for p in [profile_root,node,entry]) or not node.is_file() or not entry.is_file():
        raise SystemExit('COMPAT_LAUNCH_CONFIGURATION_INVALID')
    cwd=Path.cwd().resolve()
    partition=os.environ.get('SA_COMPAT_PARTITION','unassigned')
    key=hashlib.sha256((str(cwd).casefold()+':'+partition).encode()).hexdigest()[:24]
    home=profile_root/key
    guard=WindowsJob(1024*1024*1024,max_processes=16)
    settings={'telemetryEnabled':False,'allowedDirectories':[str(cwd)],
              'defaultShell':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
              'blockedCommands':BLOCKED,'fileReadLineLimit':200,'fileWriteLineLimit':50,
              'welcomeOnboardingEligible':False,'pendingWelcomeOnboarding':False}
    atomic_json(home/'.claude-server-commander/config.json',settings)
    env={k:v for k,v in os.environ.items() if k.upper() in SAFE_ENV}
    env.update({'USERPROFILE':str(home),'HOME':str(home),'TEMP':str(home),'TMP':str(home),
                'NODE_OPTIONS':'--max-old-space-size=512','UV_THREADPOOL_SIZE':'4',
                'DO_NOT_TRACK':'1','PUPPETEER_SKIP_DOWNLOAD':'1'})
    # Inherit protocol streams; no token, browser session, or remote-device state is forwarded.
    result=subprocess.run([str(node),str(entry)],cwd=cwd,env=env)
    return result.returncode

if __name__=='__main__':raise SystemExit(main())
