"""Registered daemons: own durable queue, shared resource governor, no implicit replay."""
from __future__ import annotations
import threading
from .common import RuntimeFault, digest, utc_now
from .store import TERMINAL


class DaemonManager:
    def __init__(self, broker, definitions=None):
        self.broker=broker
        self.store=broker.store
        self.definitions=definitions or {}
        self.lock=threading.RLock()
        with self.store.connection() as con:
            con.executescript('''
              CREATE TABLE IF NOT EXISTS daemon_slots(
                name TEXT PRIMARY KEY, owner TEXT NOT NULL, definition_hash TEXT NOT NULL,
                admission_key TEXT NOT NULL, execution_id TEXT, updated TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS daemon_restarts(
                owner TEXT NOT NULL, request_key TEXT NOT NULL, name TEXT NOT NULL,
                old_execution_id TEXT, new_execution_id TEXT,
                PRIMARY KEY(owner,request_key));
            ''')

    def definition(self,name):
        if not isinstance(name,str) or len(name)>64:
            raise RuntimeFault('INVALID_SERVICE_NAME','Registered daemon name required.')
        spec=self.definitions.get(name)
        if not spec or not spec.get('enabled',False):
            raise RuntimeFault('DAEMON_NOT_REGISTERED','Daemon must be explicitly registered and enabled.')
        return spec

    def project(self,name):
        return self.definition(name)['project']

    @staticmethod
    def _key(value):
        if not isinstance(value,str) or not 1<=len(value)<=64:
            raise RuntimeFault('INVALID_KEY','Daemon request key must be 1..64 characters.')

    def _slot(self,name,owner):
        with self.store.connection() as con:
            row=con.execute('SELECT * FROM daemon_slots WHERE name=?',(name,)).fetchone()
        if row and row['owner']!=owner:
            raise RuntimeFault('DAEMON_OWNER_CONFLICT','Daemon is owned by another principal.')
        return dict(row) if row else None

    def _public(self,name,job):
        return {'name':name,**self.broker.public(job),'kind':'daemon',
                'job_slots_used':0,'resource_governed':True,
                'application_readiness':'NOT_TESTED','automatic_restart':False,
                'reboot_survival':'NOT_QUALIFIED'}

    def start_service(self,owner,name,request_key):
        self._key(request_key)
        spec=self.definition(name)
        definition_hash=digest(spec)
        key='daemon:'+digest({'name':name,'key':request_key})
        with self.lock:
            # An old request must replay its receipt, not replace a newer instance.
            with self.store.connection() as con:
                old=con.execute('SELECT * FROM jobs WHERE owner=? AND request_key=?',(owner,key)).fetchone()
            if old:
                return {**self._public(name,dict(old)),'idempotent_replay':True}
            slot=self._slot(name,owner)
            if slot:
                if slot['definition_hash']!=definition_hash:
                    raise RuntimeFault('DAEMON_DEFINITION_DRIFT','Registered definition changed; reconcile the old instance first.')
                if slot['execution_id']:
                    job=self.store.get(slot['execution_id'],owner)
                    if job['state'] in {'LOST','UNKNOWN'}:
                        raise RuntimeFault('DAEMON_OUTCOME_UNKNOWN','Inspect the old process; automatic replacement is forbidden.')
                    if job['state'] not in TERMINAL:
                        return {**self._public(name,job),'already_active':True}
                else:
                    # A crash between slot reservation and submit is recovered using its exact key.
                    key=slot['admission_key']
            with self.store.connection(True) as con:
                con.execute('''INSERT INTO daemon_slots VALUES(?,?,?,?,?,?)
                    ON CONFLICT(name) DO UPDATE SET admission_key=excluded.admission_key,
                    execution_id=NULL,updated=excluded.updated''',
                    (name,owner,definition_hash,key,None,utc_now()))
            result=self.broker.submit(owner,spec['project'],spec['argv'],key,0)
            with self.store.connection(True) as con:
                con.execute('UPDATE daemon_slots SET execution_id=?,updated=? WHERE name=? AND owner=?',
                            (result['id'],utc_now(),name,owner))
            return self._public(name,self.store.get(result['id'],owner))

    def status(self,owner,name=None):
        if name is not None:
            self.definition(name)
            names=[name]
        else:
            names=sorted(self.definitions)
        rows=[]
        for item in names:
            spec=self.definitions[item]
            if not spec.get('enabled',False):
                rows.append({'name':item,'state':'DISABLED'}); continue
            slot=self._slot(item,owner)
            if not slot:
                rows.append({'name':item,'state':'STOPPED','application_readiness':'NOT_TESTED'}); continue
            if not slot['execution_id']:
                rows.append({'name':item,'state':'ADMISSION_PENDING','automatic_replay':False}); continue
            rows.append(self._public(item,self.store.get(slot['execution_id'],owner)))
        return {'daemons':rows,'max_active':self.broker.config['max_active'],
                'queue':'independent_from_jobs','broker_error':self.broker.last_error}

    def stop_service(self,owner,name,expected_execution_id):
        self.definition(name)
        with self.lock:
            slot=self._slot(name,owner)
            if not slot or slot['execution_id']!=expected_execution_id:
                raise RuntimeFault('DAEMON_GENERATION_CONFLICT','The expected daemon instance is no longer current.')
            result=self.store.cancel(expected_execution_id,owner)
            self.broker.wake()
            return {**self._public(name,result),'stop_requested':True}

    def restart_service(self,owner,name,request_key):
        self._key(request_key); self.definition(name)
        with self.lock:
            with self.store.connection() as con:
                op=con.execute('SELECT * FROM daemon_restarts WHERE owner=? AND request_key=?',
                               (owner,request_key)).fetchone()
            if op and op['name']!=name:
                raise RuntimeFault('IDEMPOTENCY_CONFLICT','Restart key belongs to another daemon.')
            if op and op['new_execution_id']:
                return self._public(name,self.store.get(op['new_execution_id'],owner))
            if not op:
                slot=self._slot(name,owner)
                old_id=slot['execution_id'] if slot else None
                with self.store.connection(True) as con:
                    con.execute('INSERT INTO daemon_restarts VALUES(?,?,?,?,?)',
                                (owner,request_key,name,old_id,None))
            else:
                old_id=op['old_execution_id']
            if old_id:
                old=self.store.get(old_id,owner)
                if old['state'] in {'LOST','UNKNOWN'}:
                    raise RuntimeFault('DAEMON_OUTCOME_UNKNOWN','Restart requires manual reconciliation of the old instance.')
                if old['state'] not in TERMINAL:
                    result=self.stop_service(owner,name,old_id)
                    return {**result,'restart_phase':'WAITING_FOR_STOP',
                            'next_action':'Repeat restart with the SAME request_key after the old instance terminates.'}
            result=self.start_service(owner,name,digest({'restart':request_key}))
            with self.store.connection(True) as con:
                con.execute('UPDATE daemon_restarts SET new_execution_id=? WHERE owner=? AND request_key=?',
                            (result['id'],owner,request_key))
            return {**result,'restart_phase':'START_ADMITTED'}
