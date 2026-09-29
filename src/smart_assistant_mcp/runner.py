"""A runner owns one execution. It is independent of the HTTP connection lifetime."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from .common import atomic_json, utc_now
from .store import StateStore


class WindowsJob:
    """Assign the runner BEFORE spawning: descendants inherit the Job Object."""
    def __init__(self, memory_bytes: int, max_processes: int = 32):
        self.handle = None
        if os.name != 'nt':
            return
        import ctypes as c
        from ctypes import wintypes as w
        class Basic(c.Structure):
            _fields_ = [('PerProcessUserTimeLimit',c.c_int64),('PerJobUserTimeLimit',c.c_int64),
                        ('LimitFlags',w.DWORD),('MinimumWorkingSetSize',c.c_size_t),
                        ('MaximumWorkingSetSize',c.c_size_t),('ActiveProcessLimit',w.DWORD),
                        ('Affinity',c.c_size_t),('PriorityClass',w.DWORD),('SchedulingClass',w.DWORD)]
        class IO(c.Structure):
            _fields_ = [(n,c.c_uint64) for n in ('ReadOperationCount','WriteOperationCount',
                         'OtherOperationCount','ReadTransferCount','WriteTransferCount','OtherTransferCount')]
        class Extended(c.Structure):
            _fields_ = [('BasicLimitInformation',Basic),('IoInfo',IO),
                        ('ProcessMemoryLimit',c.c_size_t),('JobMemoryLimit',c.c_size_t),
                        ('PeakProcessMemoryUsed',c.c_size_t),('PeakJobMemoryUsed',c.c_size_t)]
        kernel = c.WinDLL('kernel32', use_last_error=True)
        kernel.CreateJobObjectW.argtypes=[c.c_void_p,w.LPCWSTR]
        kernel.CreateJobObjectW.restype=w.HANDLE
        kernel.SetInformationJobObject.argtypes=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD]
        kernel.SetInformationJobObject.restype=w.BOOL
        kernel.AssignProcessToJobObject.argtypes=[w.HANDLE,w.HANDLE]
        kernel.AssignProcessToJobObject.restype=w.BOOL
        kernel.GetCurrentProcess.restype=w.HANDLE
        kernel.CloseHandle.argtypes=[w.HANDLE]
        handle=kernel.CreateJobObjectW(None,None)
        if not handle:
            raise c.WinError(c.get_last_error())
        info=Extended()
        info.BasicLimitInformation.LimitFlags=0x2000|0x200|0x8  # kill-on-close, job memory, active processes
        info.BasicLimitInformation.ActiveProcessLimit=max_processes
        info.JobMemoryLimit=memory_bytes
        if not kernel.SetInformationJobObject(handle,9,c.byref(info),c.sizeof(info)):
            error=c.get_last_error(); kernel.CloseHandle(handle); raise c.WinError(error)
        if not kernel.AssignProcessToJobObject(handle,kernel.GetCurrentProcess()):
            error=c.get_last_error(); kernel.CloseHandle(handle); raise c.WinError(error)
        # Keep this handle open until process exit; closing it also terminates this runner.
        self.handle, self.kernel = handle,kernel


def run(db_path: str, jobs_dir: str, job_id: str) -> int:
    import psutil
    store=StateStore(db_path)
    job=store.get(job_id)
    spec=json.loads(job['spec_json'])
    folder=Path(jobs_dir)/job_id
    folder.mkdir(parents=True,exist_ok=True)
    child=None
    truncation={'stdout':False,'stderr':False}
    reason=''
    input_stop=threading.Event()
    input_thread=None
    io_errors=[]
    heartbeat_write_failures=0
    try:
        if job['state'] != 'STARTING':
            return 2
        created=psutil.Process().create_time()
        if not store.transition(job_id,{'STARTING'},'STARTING',runner_pid=os.getpid(),runner_created=created):
            return 2
        guard=WindowsJob(int(spec['memory_gib']*2**30))
        if store.get(job_id)['cancel_requested']:
            store.transition(job_id,{'STARTING'},'CANCELLED',detail='Cancelled before child creation')
            return 0
        if spec['timeout_seconds']==0 and spec.get('kind')!='daemon':
            raise ValueError('Unbounded jobs are forbidden')
        env={k:v for k,v in os.environ.items() if k.upper() in
             {'SYSTEMROOT','WINDIR','PATH','COMSPEC','TEMP','TMP','USERPROFILE','HOME','PATHEXT','APPDATA','LOCALAPPDATA'}}
        env['PYTHONUNBUFFERED']='1'
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name=='nt' else 0
        child=subprocess.Popen(spec['argv'],cwd=spec['cwd'],env=env,stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,
                               creationflags=flags,start_new_session=(os.name!='nt'))
        store.transition(job_id,{'STARTING'},'RUNNING',child_pid=child.pid)
        cap=int(spec.get('max_output_bytes',32*1024*1024))
        def drain(stream,name):
            used=0
            try:
                with (folder/(name+'.log')).open('wb',buffering=0) as target:
                    while True:
                        block=os.read(stream.fileno(),16384)
                        if not block:
                            break
                        remaining=max(0,cap-used)
                        if remaining:
                            target.write(block[:remaining]); used+=min(len(block),remaining)
                        if len(block)>remaining:
                            truncation[name]=True
            except OSError as exc:
                io_errors.append(type(exc).__name__)
            finally:
                stream.close()
        threads=[threading.Thread(target=drain,args=(getattr(child,n),n),daemon=True) for n in ('stdout','stderr')]
        for t in threads: t.start()
        def feed_input():
            while not input_stop.is_set() and child.poll() is None:
                for entry in store.claim_inputs(job_id):
                    try:
                        child.stdin.write(entry['text'].encode('utf-8')); child.stdin.flush()
                    except (BrokenPipeError,OSError,ValueError):
                        return
                input_stop.wait(0.1)
        if spec.get('kind')!='daemon':
            input_thread=threading.Thread(target=feed_input,name='job-input',daemon=True)
            input_thread.start()
        started=time.monotonic()
        # PID and RUNNING are already durable; fast jobs need only a final receipt.
        next_heartbeat=started+2.0
        timeout=spec['timeout_seconds']
        if timeout==0 and spec.get('kind')!='daemon': raise ValueError('Unbounded jobs are forbidden')
        while child.poll() is None:
            current=store.get(job_id)
            if current['cancel_requested'] or io_errors or (timeout>0 and time.monotonic()-started>timeout):
                reason='cancel_requested' if current['cancel_requested'] else 'output_io_error' if io_errors else 'execution_timeout'
                if os.name=='nt':
                    for p in reversed(psutil.Process(child.pid).children(recursive=True)):
                        try: p.terminate()
                        except psutil.Error: pass
                    child.terminate()
                else:
                    os.killpg(child.pid,signal.SIGTERM)
                try: child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    if os.name=='nt': child.kill()
                    else: os.killpg(child.pid,signal.SIGKILL)
                    child.wait(timeout=3)
                break
            if time.monotonic()>=next_heartbeat:
                try:
                    atomic_json(folder/'heartbeat.json',{'runner_pid':os.getpid(),'runner_created':created,
                                'child_pid':child.pid,'at':utc_now(),'output_truncated':truncation})
                except PermissionError:
                    heartbeat_write_failures+=1
                next_heartbeat=time.monotonic()+2.0
            # Wake on process completion rather than sleeping a fixed interval.
            try: child.wait(timeout=0.05 if time.monotonic()-started<1 else 0.2)
            except subprocess.TimeoutExpired: pass
        input_stop.set()
        for t in threads: t.join(timeout=1)
        if any(t.is_alive() for t in threads) or io_errors:
            reason=reason or 'output_incomplete'
        state='CANCELLED' if reason=='cancel_requested' else 'COMPLETED' if child.returncode==0 and not reason else 'FAILED'
        receipt={'id':job_id,'state':state,'exit_code':child.returncode,'at':utc_now(),
                 'detail':reason,'output_truncated':truncation,'output_errors':io_errors,
                 'windows_job_object':guard.handle is not None,'heartbeat_write_failures':heartbeat_write_failures}
        atomic_json(folder/'receipt.json',receipt)
        store.transition(job_id,{'RUNNING','STARTING'},state,exit_code=child.returncode,detail=reason)
        return 0
    except Exception as exc:
        detail=type(exc).__name__+': '+str(exc)[:400]
        atomic_json(folder/'receipt.json',{'id':job_id,'state':'FAILED','detail':detail,'at':utc_now()})
        store.transition(job_id,{'RUNNING','STARTING'},'FAILED',detail=detail)
        return 1
    finally:
        input_stop.set()
        if child:
            if child.poll() is None:
                if os.name=='nt': child.kill()
                else:
                    try: os.killpg(child.pid,signal.SIGKILL)
                    except ProcessLookupError: pass
            if child.stdin: child.stdin.close()
            if input_thread: input_thread.join(timeout=1)
        # On Windows the OS closes the job handle on exit, killing remaining descendants.


if __name__=='__main__':
    raise SystemExit(run(*sys.argv[1:4]))
