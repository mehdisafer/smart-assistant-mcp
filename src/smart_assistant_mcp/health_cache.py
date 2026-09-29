"""Owner-filtered execution counters refreshed outside the HTTP request path."""
from __future__ import annotations
import threading
import time

class HealthCache:
    def __init__(self, store, interval=1.0, clock=time.monotonic):
        self.store=store
        self.interval=max(.25,float(interval))
        self.clock=clock
        self.lock=threading.Lock()
        self.rows={}
        self.sample_at=None
        self.last_error=None
        self.stop_event=threading.Event()
        self.thread=None

    def refresh(self):
        try:
            with self.store.connection() as con:
                rows=con.execute('SELECT owner,state,count(*) n FROM jobs GROUP BY owner,state').fetchall()
            values={}
            for row in rows: values.setdefault(row['owner'],{})[row['state']]=row['n']
            with self.lock:
                self.rows=values;self.sample_at=self.clock();self.last_error=None
        except Exception as exc:
            with self.lock:self.last_error=type(exc).__name__

    def snapshot(self, owner):
        with self.lock:
            age=None if self.sample_at is None else max(0.0,self.clock()-self.sample_at)
            return {'counts':None if age is None else dict(self.rows.get(owner,{})),
                    'age_seconds':None if age is None else round(age,3),
                    'stale':age is None or age>max(3.0,3*self.interval),
                    'error_code':self.last_error,'collection_on_call':False}

    def _loop(self):
        while not self.stop_event.is_set():
            self.refresh();self.stop_event.wait(self.interval)

    def start(self):
        if self.thread and self.thread.is_alive():return
        self.stop_event.clear()
        self.thread=threading.Thread(target=self._loop,name='mcp-health-counters',daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=4)
