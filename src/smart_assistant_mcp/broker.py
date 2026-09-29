from __future__ import annotations

import codecs
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from .common import RuntimeFault
from .filesystem import FileLock, PathPolicy
from .governor import Governor
from .store import StateStore, TERMINAL


class Broker:
    def __init__(self, store: StateStore, governor: Governor, policy: PathPolicy,
                 jobs_dir: Path, config: dict | None = None):
        self.store,self.governor,self.policy,self.jobs_dir=store,governor,policy,jobs_dir
        self.config={'enabled':False,'queue_limit':64,'memory_gib':2.0,'max_active':2,
                     'max_timeout_seconds':3600,'max_output_bytes':32*1024*1024,**(config or {})}
        self.stop_event=threading.Event()
        self.thread=None
        self.processes={}
        self.lock=None
        self.last_error=None
        self.wake_event=threading.Event()
        self.owned_leases=set()

    @staticmethod
    def public(job):
        return {k:job[k] for k in ('id','owner','state','created','updated','runner_pid','child_pid',
                                  'exit_code','cancel_requested','detail')}

    def submit(self,owner,project,argv,request_key,timeout_seconds=300):
        if not self.config['enabled']:
            raise RuntimeFault('EXECUTION_DISABLED','Native process execution has not been enabled by the operator.')
        if not isinstance(argv,list) or not argv or len(argv)>128 or any(not isinstance(a,str) or '\x00' in a for a in argv):
            raise RuntimeFault('INVALID_ARGV','Provide a nonempty argument vector, not a shell string.')
        if sum(len(a) for a in argv)>32768:
            raise RuntimeFault('COMMAND_TOO_LARGE','Argument vector exceeds 32 KiB.')
        executable=Path(argv[0])
        if not executable.is_absolute() or not executable.is_file():
            raise RuntimeFault('ABSOLUTE_EXECUTABLE_REQUIRED','Use the full path to the executable.')
        if not (type(timeout_seconds) is int and (1<=timeout_seconds<=self.config['max_timeout_seconds'] or (timeout_seconds==0 and self.config.get('kind')=='daemon'))):
            raise RuntimeFault('INVALID_TIMEOUT','Execution timeout is outside the configured limit.')
        cwd=self.policy.resolve(project,'',True)
        spec={'argv':argv,'cwd':str(cwd),'timeout_seconds':timeout_seconds,
              'memory_gib':self.config['memory_gib'],'max_output_bytes':self.config['max_output_bytes']}
        if self.config.get('kind')=='daemon': spec['kind']='daemon'
        row,created=self.store.submit(owner,request_key,spec,int(self.config.get('priority',2)),self.config['queue_limit'])
        if created: self.wake()
        return {**self.public(row),'new_admission':created,'security_boundary':'operating-system account, not cwd'}

    def wake(self):
        self.wake_event.set()

    def start(self):
        if self.thread and self.thread.is_alive(): return
        self.jobs_dir.mkdir(parents=True,exist_ok=True)
        self.lock=FileLock(self.jobs_dir.parent/'broker.lock')
        self.lock.__enter__()
        self.stop_event.clear()
        self.thread=threading.Thread(target=self._loop,name='mcp-execution-broker',daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.wake()
        if self.thread: self.thread.join(timeout=5)
        if self.lock: self.lock.__exit__(None,None,None); self.lock=None
        # Intentionally do not kill accepted runner processes here.

    def _alive(self,job):
        if not job['runner_pid'] or not job['runner_created']: return False
        try:
            p=psutil.Process(job['runner_pid'])
            return abs(p.create_time()-job['runner_created'])<0.01 and p.is_running() and p.status()!=psutil.STATUS_ZOMBIE
        except psutil.Error: return False

    def tick(self):
        for job_id,p in list(self.processes.items()):
            if p.poll() is not None:
                p.wait(); del self.processes[job_id]
        for job in self.store.jobs({'STARTING','RUNNING'},1000):
            spec=json.loads(job['spec_json'])
            if self._alive(job):
                self.governor.restore(job['id'],spec['memory_gib'],job['priority'])
                self.owned_leases.add(job['id'])
                try:
                    p=psutil.Process(job['runner_pid'])
                    observed=sum(x.memory_info().rss for x in [p,*p.children(recursive=True)]) / 2**30
                    self.governor.observed(job['id'],observed)
                except psutil.Error: pass
            else:
                receipt=self.jobs_dir/job['id']/'receipt.json'
                if receipt.is_file():
                    data=json.loads(receipt.read_text())
                    self.store.transition(job['id'],{'STARTING','RUNNING'},data['state'],
                                          exit_code=data.get('exit_code'),detail=data.get('detail',''))
                elif job['state']=='RUNNING':
                    self.store.transition(job['id'],{'RUNNING'},'LOST',detail='Runner disappeared; never replay automatically.')
                elif (datetime.now(timezone.utc)-datetime.fromisoformat(job['updated'])).total_seconds()>120:
                    self.store.transition(job['id'],{'STARTING'},'UNKNOWN',detail='Runner start is ambiguous; operator reconciliation required.')
        active=self.store.jobs({'STARTING','RUNNING'},1000)
        active_ids={x['id'] for x in active}
        for key in list(self.owned_leases):
            if key not in active_ids:
                self.governor.release(key)
                self.owned_leases.discard(key)
        for queued in self.store.jobs({'QUEUED'},1000):
            if queued['cancel_requested']:
                self.store.transition(queued['id'],{'QUEUED'},'CANCELLED',detail='Cancelled in queue')
        if not self.config['enabled']: return
        for job in self.store.jobs({'QUEUED'},64):
            if job['cancel_requested']:
                self.store.transition(job['id'],{'QUEUED'},'CANCELLED',detail='Cancelled in queue')
                continue
            if len(active_ids)>=self.config['max_active']: break
            spec=json.loads(job['spec_json'])
            try: self.governor.acquire(job['id'],spec['memory_gib'],job['priority'],True)
            except RuntimeFault: continue
            if not self.store.transition(job['id'],{'QUEUED'},'STARTING'):
                self.governor.release(job['id']); continue
            try:
                command=self.config.get('runner_command') or [sys.executable,'-m','smart_assistant_mcp.runner']
                command=[*command,str(self.store.path),str(self.jobs_dir),job['id']]
                flags=(subprocess.DETACHED_PROCESS|subprocess.CREATE_NEW_PROCESS_GROUP) if os.name=='nt' else 0
                # No authentication tokens are propagated to the runner.
                environment={k:v for k,v in os.environ.items() if k.upper() in
                             {'SYSTEMROOT','WINDIR','PATH','COMSPEC','TEMP','TMP','USERPROFILE','HOME','PATHEXT',
                              'APPDATA','LOCALAPPDATA','PYTHONPATH','SA_MCP_ROOT','SA_MCP_SOURCE'}}
                process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL,env=environment,creationflags=flags,
                                         start_new_session=(os.name!='nt'))
                self.processes[job['id']]=process
                self.owned_leases.add(job['id'])
                active_ids.add(job['id'])
            except Exception as exc:
                self.store.transition(job['id'],{'STARTING'},'FAILED',detail='Spawn failed: '+type(exc).__name__)
                self.governor.release(job['id'])

    def _loop(self):
        while not self.stop_event.is_set():
            self.wake_event.clear()
            try: self.tick(); self.last_error=None
            except Exception as exc: self.last_error=type(exc).__name__+': '+str(exc)[:300]
            self.wake_event.wait(0.5 if self.owned_leases else 2.0)

    def read(self,job_id,owner,stream='stdout',cursor=0,length=16384):
        if stream not in {'stdout','stderr'} or cursor<0 or not 4<=length<=65536:
            raise RuntimeFault('INVALID_RANGE','Invalid stream, byte cursor or read length.')
        job=self.store.get(job_id,owner)
        if not re.fullmatch('[0-9a-f]{32}',job_id):
            raise RuntimeFault('INVALID_ID','Invalid execution identifier.')
        path=self.jobs_dir/job_id/(stream+'.log')
        raw=b''
        size=0
        if path.is_file():
            with path.open('rb') as f:
                size=path.stat().st_size
                if cursor>size: raise RuntimeFault('INVALID_CURSOR','Cursor exceeds stored output.')
                f.seek(cursor); raw=f.read(length)
        decoder=codecs.getincrementaldecoder('utf-8')('replace')
        text=decoder.decode(raw,final=job['state'] in TERMINAL and cursor+len(raw)>=size)
        remaining,_=decoder.getstate()
        next_cursor=cursor+len(raw)-len(remaining)
        marker=self.jobs_dir/job_id/('receipt.json' if job['state'] in TERMINAL else 'heartbeat.json')
        meta=json.loads(marker.read_text()) if marker.is_file() else {}
        return {'id':job_id,'state':job['state'],'stream':stream,'cursor':cursor,'next_cursor':next_cursor,
                'text':text,'output_truncation_known':bool(meta),'output_truncated':meta.get('output_truncated',{}).get(stream,False),
                'exit_code':job['exit_code']}
