"""Native Windows inspection and explicitly registered service control. No shell."""
from __future__ import annotations
import json
import os
import re
import socket
import threading
import time
import psutil
from .common import RuntimeFault, canonical, digest, utc_now

_DLL_HANDLES=[]
_DLL_LOCK=threading.Lock()

def ensure_windows_bindings():
    # Isolated -I/-S launchers do not execute pywin32's site .pth bootstrap.
    # Register the installed DLL directory explicitly; retain the handle for process lifetime.
    import sys
    from pathlib import Path
    if os.name!='nt':
        raise RuntimeFault('UNSUPPORTED_PLATFORM','Windows bindings require Windows.')
    with _DLL_LOCK:
        if _DLL_HANDLES:return
        for entry in sys.path:
            directory=Path(entry)/'pywin32_system32'
            if directory.is_dir():
                _DLL_HANDLES.append(os.add_dll_directory(str(directory)))
                return
        raise RuntimeFault('NATIVE_BINDINGS_UNAVAILABLE','The installed pywin32 DLL directory is not on the configured dependency path.')



class WindowsNative:
    def __init__(self, store, services=None, protected_services=None, refresh_seconds=15):
        self.store=store
        self.registered={k.casefold():v for k,v in (services or {}).items()}
        self.protected={str(x).casefold() for x in (protected_services or [])}
        self.refresh_seconds=max(5,float(refresh_seconds))
        self.lock=threading.RLock()
        self.action_lock=threading.Lock()
        self.rows=[]
        self.snapshot_at=None
        self.last_error=None
        self.last_collection_ms=None
        self.stop_event=threading.Event()
        self.thread=None
        with store.connection() as con:
            con.execute('''CREATE TABLE IF NOT EXISTS native_service_operations(
              owner TEXT NOT NULL, request_key TEXT NOT NULL, request_hash TEXT NOT NULL,
              state TEXT NOT NULL, result_json TEXT, at TEXT NOT NULL,
              PRIMARY KEY(owner,request_key))''')

    @staticmethod
    def _windows():
        if os.name!='nt':
            raise RuntimeFault('UNSUPPORTED_PLATFORM','This operation requires Windows.')

    @staticmethod
    def _name(name):
        if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_. -]{1,128}',name):
            raise RuntimeFault('INVALID_SERVICE_NAME','An exact service name is required.')

    @staticmethod
    def _service_row(s):
        # binpath can contain credentials. Never return it.
        return {'name':s.name(),'display_name':s.display_name(),'status':s.status(),
                'pid':s.pid(),'start_type':s.start_type()}

    def service_status(self,name):
        self._windows(); self._name(name)
        try:
            row=self._service_row(psutil.win_service_get(name))
            return {**row,'observed_at':utc_now(),'application_readiness':'NOT_TESTED'}
        except psutil.NoSuchProcess:
            raise RuntimeFault('SERVICE_NOT_FOUND','No service with this exact name.')
        except psutil.AccessDenied:
            raise RuntimeFault('ACCESS_DENIED','Service account cannot inspect this service.')

    def refresh(self):
        self._windows()
        started=time.perf_counter()
        ensure_windows_bindings()
        import win32service
        manager=win32service.OpenSCManager(None,None,win32service.SC_MANAGER_ENUMERATE_SERVICE)
        try:
            raw=win32service.EnumServicesStatusEx(
                manager,win32service.SERVICE_WIN32,win32service.SERVICE_STATE_ALL)
        finally:
            win32service.CloseServiceHandle(manager)
        states={
            win32service.SERVICE_STOPPED:"stopped",
            win32service.SERVICE_START_PENDING:"start_pending",
            win32service.SERVICE_STOP_PENDING:"stop_pending",
            win32service.SERVICE_RUNNING:"running",
            win32service.SERVICE_CONTINUE_PENDING:"continue_pending",
            win32service.SERVICE_PAUSE_PENDING:"pause_pending",
            win32service.SERVICE_PAUSED:"paused",
        }
        rows=[{"name":r["ServiceName"],"display_name":r["DisplayName"],
               "status":states.get(r["CurrentState"],"unknown"),
               "pid":int(r.get("ProcessId") or 0),"start_type":None}
              for r in raw]
        with self.lock:
            self.rows=rows; self.snapshot_at=time.monotonic(); self.last_error=None
            self.denied=0; self.last_collection_ms=(time.perf_counter()-started)*1000

    def _loop(self):
        while not self.stop_event.is_set():
            try: self.refresh()
            except Exception as exc:
                with self.lock: self.last_error=getattr(exc,'code',type(exc).__name__)
            self.stop_event.wait(self.refresh_seconds)

    def start(self):
        if self.thread and self.thread.is_alive(): return
        self.stop_event.clear()
        self.thread=threading.Thread(target=self._loop,name='mcp-service-snapshot',daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread: self.thread.join(timeout=2)

    def service_list(self,limit=100,prefix=''):
        if type(limit) is not int or not 1<=limit<=500 or len(prefix)>128:
            raise RuntimeFault('INVALID_RANGE','Bound service inventory to 1..500 entries.')
        with self.lock:
            rows=[dict(r) for r in self.rows if r['name'].casefold().startswith(prefix.casefold())]
            age=time.monotonic()-self.snapshot_at if self.snapshot_at is not None else None
            error=self.last_error
        rows.sort(key=lambda r:r['name'].casefold())
        return {'services':rows[:limit],'total_visible':len(rows),'truncated':len(rows)>limit,
                'snapshot_age_seconds':round(age,3) if age is not None else None,
                'state':'DEGRADED' if error else 'WARMING' if age is None else 'STALE' if age>45 else 'READY',
                'error_code':error,'command_lines_exposed':False,'collection_on_call':False,
                'inventory_detail':'basic','detail_tool':'service_status',
                'collection_ms':round(self.last_collection_ms,3) if self.last_collection_ms is not None else None}

    def service_project(self,name):
        self._name(name)
        if name.casefold() in self.protected or 'desktop' in name.casefold() or 'commander' in name.casefold():
            raise RuntimeFault('PROTECTED_SERVICE','Configured control-plane and compatibility services are protected.')
        spec=self.registered.get(name.casefold())
        if not spec or not spec.get('enabled',False):
            raise RuntimeFault('SERVICE_NOT_REGISTERED','Service control is disabled unless explicitly registered.')
        return spec['project']

    def service_control(self,owner,name,action,request_key):
        self._windows(); self.service_project(name)
        if action not in {'start','stop','restart'}:
            raise RuntimeFault('INVALID_ACTION','Use start, stop or restart.')
        if not request_key or len(request_key)>128:
            raise RuntimeFault('INVALID_KEY','A stable request key (1..128 chars) is required.')
        request_hash=digest({'name':name.casefold(),'action':action})
        with self.action_lock:
            with self.store.connection(True) as con:
                old=con.execute('SELECT * FROM native_service_operations WHERE owner=? AND request_key=?',(owner,request_key)).fetchone()
                if old:
                    if old['request_hash']!=request_hash:
                        raise RuntimeFault('IDEMPOTENCY_CONFLICT','This key belongs to another service operation.')
                    return json.loads(old['result_json']) if old['result_json'] else {
                        'state':'UNKNOWN','action':action,'service':name,'automatic_replay':False}
                con.execute('INSERT INTO native_service_operations VALUES(?,?,?,?,?,?)',
                    (owner,request_key,request_hash,'STARTING',None,utc_now()))
            try:
                result=self._control(name,action)
            except Exception as exc:
                code=getattr(exc,'winerror',None)
                result={'state':'FAILED' if code==5 else 'UNKNOWN','service':name,'action':action,
                        'error_code':'ACCESS_DENIED' if code==5 else getattr(exc,'code',type(exc).__name__),
                        'automatic_replay':False}
            with self.store.connection(True) as con:
                con.execute('UPDATE native_service_operations SET state=?,result_json=?,at=? WHERE owner=? AND request_key=?',
                    (result['state'],canonical(result),utc_now(),owner,request_key))
            return result

    def _control(self,name,action):
        ensure_windows_bindings()
        import win32service as ws
        rights=ws.SERVICE_QUERY_STATUS
        if action in {'start','restart'}: rights|=ws.SERVICE_START
        if action in {'stop','restart'}: rights|=ws.SERVICE_STOP
        manager=ws.OpenSCManager(None,None,ws.SC_MANAGER_CONNECT)
        handle=None
        try:
            handle=ws.OpenService(manager,name,rights)
            current=ws.QueryServiceStatus(handle)[1]
            if action in {'stop','restart'} and current!=ws.SERVICE_STOPPED:
                if current!=ws.SERVICE_STOP_PENDING:
                    ws.ControlService(handle,ws.SERVICE_CONTROL_STOP)
                deadline=time.monotonic()+5
                while ws.QueryServiceStatus(handle)[1]!=ws.SERVICE_STOPPED:
                    if time.monotonic()>=deadline:
                        return {'state':'PENDING','service':name,'action':action,'phase':'STOPPING',
                                'automatic_restart':False,'next_action':'Inspect service_status before issuing a new operation.'}
                    time.sleep(.1)
            if action in {'start','restart'}:
                current=ws.QueryServiceStatus(handle)[1]
                if current not in {ws.SERVICE_RUNNING,ws.SERVICE_START_PENDING}:
                    ws.StartService(handle,None)
            observed=self.service_status(name)
            target='stopped' if action=='stop' else 'running'
            return {'state':'COMPLETED' if observed['status']==target else 'PENDING',
                    'service':name,'action':action,'observed':observed}
        finally:
            if handle is not None: ws.CloseServiceHandle(handle)
            ws.CloseServiceHandle(manager)

    @staticmethod
    def process_inspect(pid,expected_create_time=None):
        if type(pid) is not int or pid<=0:
            raise RuntimeFault('INVALID_PROCESS','A positive PID is required.')
        try:
            p=psutil.Process(pid)
            with p.oneshot():
                created=p.create_time()
                if expected_create_time is not None and abs(created-float(expected_create_time))>.01:
                    raise RuntimeFault('PID_REUSED','PID creation time differs from the supplied identity.')
                return {'pid':pid,'created':created,'name':p.name(),'ppid':p.ppid(),
                    'status':p.status(),'memory_mib':round(p.memory_info().rss/2**20,3),
                    'threads':p.num_threads(),'command_lines_exposed':False}
        except psutil.NoSuchProcess:
            raise RuntimeFault('PROCESS_NOT_FOUND','Process no longer exists.')
        except psutil.AccessDenied:
            raise RuntimeFault('ACCESS_DENIED','Process is not accessible to this service account.')

    @staticmethod
    def port_probe(port,host='127.0.0.1',timeout_ms=500):
        if host not in {'127.0.0.1','::1'} or type(port) is not int or not 1<=port<=65535:
            raise RuntimeFault('INVALID_ENDPOINT','Only explicit loopback TCP endpoints are supported.')
        if type(timeout_ms) is not int or not 20<=timeout_ms<=1000:
            raise RuntimeFault('INVALID_TIMEOUT','Probe timeout must be 20..1000 ms.')
        started=time.perf_counter()
        try:
            with socket.create_connection((host,port),timeout=timeout_ms/1000): pass
            status='OPEN'
        except (ConnectionRefusedError,socket.timeout,OSError) as exc:
            status='TIMEOUT' if isinstance(exc,socket.timeout) else 'CLOSED_OR_DENIED'
        return {'host':host,'port':port,'tcp_status':status,
                'latency_ms':round((time.perf_counter()-started)*1000,3),
                'application_readiness':'NOT_TESTED'}

    @staticmethod
    def scheduled_task_status(task_path):
        WindowsNative._windows()
        if not isinstance(task_path,str) or not task_path.startswith('\\') or len(task_path)>260 or '..' in task_path or '*' in task_path:
            raise RuntimeFault('INVALID_TASK_PATH','Supply one exact absolute Task Scheduler path.')
        ensure_windows_bindings()
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        scheduler=folder_object=task=None
        try:
            scheduler=win32com.client.Dispatch('Schedule.Service'); scheduler.Connect()
            folder,_,name=task_path.rpartition('\\')
            folder_object=scheduler.GetFolder(folder or '\\')
            task=folder_object.GetTask(name)
            states={0:'UNKNOWN',1:'DISABLED',2:'QUEUED',3:'READY',4:'RUNNING'}
            return {'task_path':task_path,'state':states.get(task.State,'UNKNOWN'),
                'enabled':bool(task.Enabled),'last_result':int(task.LastTaskResult),
                'last_run':str(task.LastRunTime),'next_run':str(task.NextRunTime),
                'actions_exposed':False}
        except pythoncom.com_error as exc:
            code=exc.hresult & 0xffffffff
            raise RuntimeFault('ACCESS_DENIED' if code==0x80070005 else 'TASK_QUERY_FAILED',
                               'Task Scheduler query failed (HRESULT 0x%08x).'%code)
        finally:
            task=None
            folder_object=None
            scheduler=None
            pythoncom.CoUninitialize()
