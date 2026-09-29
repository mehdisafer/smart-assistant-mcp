from __future__ import annotations

import os
import threading
import time
import psutil
from .common import RuntimeFault

PROTECTED_NAMES={"system","registry","smss.exe","csrss.exe","wininit.exe","services.exe",
                 "lsass.exe","winlogon.exe","fontdrvhost.exe"}

class ProcessManager:
    """Fast cached process discovery. Detailed per-process metrics are intentionally on process_inspect."""
    def __init__(self,refresh_seconds:float=5.0,clock=time.monotonic):
        self.self_pid=os.getpid()
        self.refresh_seconds=max(1.0,float(refresh_seconds))
        self.clock=clock
        self.lock=threading.RLock()
        self.snapshot=[]
        self.snapshot_at=float("-inf")
        self.last_error=None
        self.last_collection_ms=None
        self.stop_event=threading.Event()
        self.thread=None

    @staticmethod
    def _collect_windows():
        import ctypes as c
        from ctypes import wintypes as w
        TH32CS_SNAPPROCESS=0x00000002
        INVALID_HANDLE_VALUE=c.c_void_p(-1).value
        class Entry(c.Structure):
            _fields_=[("dwSize",w.DWORD),("cntUsage",w.DWORD),("th32ProcessID",w.DWORD),
                ("th32DefaultHeapID",c.c_size_t),("th32ModuleID",w.DWORD),("cntThreads",w.DWORD),
                ("th32ParentProcessID",w.DWORD),("pcPriClassBase",c.c_long),("dwFlags",w.DWORD),
                ("szExeFile",w.WCHAR*260)]
        kernel=c.WinDLL("kernel32",use_last_error=True)
        kernel.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD]
        kernel.CreateToolhelp32Snapshot.restype=w.HANDLE
        kernel.Process32FirstW.argtypes=[w.HANDLE,c.POINTER(Entry)]
        kernel.Process32FirstW.restype=w.BOOL
        kernel.Process32NextW.argtypes=[w.HANDLE,c.POINTER(Entry)]
        kernel.Process32NextW.restype=w.BOOL
        kernel.CloseHandle.argtypes=[w.HANDLE]
        kernel.CloseHandle.restype=w.BOOL
        handle=kernel.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0)
        if handle in (None,0,INVALID_HANDLE_VALUE):
            raise c.WinError(c.get_last_error())
        rows=[]; entry=Entry(); entry.dwSize=c.sizeof(entry)
        try:
            ok=kernel.Process32FirstW(handle,c.byref(entry))
            while ok:
                rows.append({"pid":int(entry.th32ProcessID),"ppid":int(entry.th32ParentProcessID),
                    "name":entry.szExeFile or None,"status":"running"})
                ok=kernel.Process32NextW(handle,c.byref(entry))
        finally:
            kernel.CloseHandle(handle)
        return rows

    @staticmethod
    def _collect_portable():
        rows=[]
        for p in psutil.process_iter(["pid","ppid","name","status"]):
            try: rows.append(dict(p.info))
            except (psutil.NoSuchProcess,psutil.AccessDenied): continue
        return rows

    def _collect(self):
        return self._collect_windows() if os.name=="nt" else self._collect_portable()

    def refresh(self):
        started=time.perf_counter()
        try:
            rows=self._collect()
            elapsed=(time.perf_counter()-started)*1000
            with self.lock:
                self.snapshot=rows; self.snapshot_at=self.clock(); self.last_error=None
                self.last_collection_ms=elapsed
            return len(rows)
        except Exception as exc:
            with self.lock:self.last_error=type(exc).__name__
            raise

    def _loop(self):
        while not self.stop_event.is_set():
            try:self.refresh()
            except Exception:pass
            self.stop_event.wait(self.refresh_seconds)

    def start(self):
        if self.thread and self.thread.is_alive():return
        self.stop_event.clear()
        self.thread=threading.Thread(target=self._loop,name="mcp-process-snapshot",daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=3)

    def list(self,limit:int=100,sort_by:str="name")->dict:
        if type(limit) is not int or not 1<=limit<=500:
            raise RuntimeFault("INVALID_LIMIT","limit must be between 1 and 500.")
        if sort_by not in {"pid","name"}:
            raise RuntimeFault("EXPENSIVE_SORT_DISABLED",
                "Fast inventory supports pid or name. Use process_inspect for fresh CPU/memory details.")
        with self.lock:
            rows=[dict(x) for x in self.snapshot]; at=self.snapshot_at; err=self.last_error; ms=self.last_collection_ms
        if not rows:
            self.refresh()
            with self.lock:
                rows=[dict(x) for x in self.snapshot];at=self.snapshot_at;err=self.last_error;ms=self.last_collection_ms
        key=(lambda x:x["pid"]) if sort_by=="pid" else (lambda x:(x["name"] or "").casefold())
        rows.sort(key=key)
        age=max(0.0,self.clock()-at) if at!=float("-inf") else None
        return {"processes":rows[:limit],"total_visible":len(rows),"truncated":len(rows)>limit,
                "sort_by":sort_by,"inventory_detail":"basic","detail_tool":"process_inspect",
                "command_lines_exposed":False,"snapshot_age_seconds":round(age,3) if age is not None else None,
                "snapshot_stale":age is None or age>max(15.0,self.refresh_seconds*3),
                "snapshot_error":err,"collection_ms":round(ms,3) if ms is not None else None}

    def terminate(self,pid:int,expected_create_time:float,force:bool=False)->dict:
        if type(pid) is not int or pid<=4 or type(expected_create_time) not in (int,float):
            raise RuntimeFault("INVALID_PROCESS","A valid PID and create time are required.")
        if pid==self.self_pid:
            raise RuntimeFault("PROTECTED_PROCESS","The MCP service cannot terminate itself.")
        try:
            p=psutil.Process(pid);created=p.create_time()
            if abs(created-float(expected_create_time))>0.05:
                raise RuntimeFault("PID_REUSED","Process creation time does not match.")
            name=(p.name() or "").casefold()
            if name in PROTECTED_NAMES:
                raise RuntimeFault("PROTECTED_PROCESS","Critical Windows process is protected.")
            before={"pid":pid,"name":p.name(),"created":created}
            if force:p.kill()
            else:p.terminate()
            try:p.wait(timeout=5)
            except psutil.TimeoutExpired:
                if not force:return {**before,"requested":"terminate","exited":False,"retry_with_force":True}
                raise RuntimeFault("TERMINATE_TIMEOUT","Process did not exit.",True)
            return {**before,"requested":"kill" if force else "terminate","exited":True}
        except psutil.NoSuchProcess:
            raise RuntimeFault("PROCESS_NOT_FOUND","Process no longer exists.")
        except psutil.AccessDenied:
            raise RuntimeFault("PROCESS_ACCESS_DENIED","Service account cannot terminate this process.")
