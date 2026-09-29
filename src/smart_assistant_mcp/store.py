from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

from .common import RuntimeFault, canonical, digest, utc_now

TERMINAL = {'COMPLETED', 'FAILED', 'CANCELLED', 'LOST', 'UNKNOWN'}


class StateStore:
    """Durable admissions and receipts. Connections are always closed explicitly."""
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as con:
            con.execute('PRAGMA journal_mode=WAL')
            con.executescript('''
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, owner TEXT NOT NULL,
                    request_key TEXT NOT NULL, request_hash TEXT NOT NULL,
                    state TEXT NOT NULL, priority INTEGER NOT NULL,
                    spec_json TEXT NOT NULL, created TEXT NOT NULL,
                    updated TEXT NOT NULL, runner_pid INTEGER,
                    runner_created REAL, child_pid INTEGER,
                    exit_code INTEGER, cancel_requested INTEGER NOT NULL DEFAULT 0,
                    detail TEXT NOT NULL DEFAULT '',
                    UNIQUE(owner, request_key)
                );
                CREATE INDEX IF NOT EXISTS ix_jobs_state ON jobs(state,priority,created);
                CREATE INDEX IF NOT EXISTS ix_jobs_owner_state ON jobs(owner,state);
                CREATE INDEX IF NOT EXISTS ix_jobs_owner ON jobs(owner);
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT, kind TEXT NOT NULL, at TEXT NOT NULL,
                    detail_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS inputs (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL, request_key TEXT NOT NULL,
                    text TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(job_id, request_key)
                );
            ''')

    @contextmanager
    def connection(self, immediate: bool = False):
        con = sqlite3.connect(self.path, timeout=3, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA busy_timeout=3000')
        con.execute('PRAGMA synchronous=FULL')
        try:
            if immediate:
                con.execute('BEGIN IMMEDIATE')
            yield con
            if immediate:
                con.commit()
        except BaseException:
            if immediate:
                con.rollback()
            raise
        finally:
            con.close()

    def _event(self, con, job_id, kind, detail=None):
        con.execute('INSERT INTO events(job_id,kind,at,detail_json) VALUES(?,?,?,?)',
                    (job_id, kind, utc_now(), canonical(detail or {})))

    def submit(self, owner: str, request_key: str, spec: dict,
               priority: int, queue_limit: int = 64) -> tuple[dict, bool]:
        if not request_key or len(request_key) > 128:
            raise RuntimeFault('INVALID_KEY', 'A nonempty idempotency key (max 128 chars) is required.')
        request_hash = digest({'spec': spec, 'priority': priority})
        with self.connection(True) as con:
            existing = con.execute('SELECT * FROM jobs WHERE owner=? AND request_key=?',
                                   (owner, request_key)).fetchone()
            if existing:
                if existing['request_hash'] != request_hash:
                    raise RuntimeFault('IDEMPOTENCY_CONFLICT', 'This key belongs to a different operation.')
                return dict(existing), False
            pending = con.execute("SELECT count(*) FROM jobs WHERE state IN ('QUEUED','STARTING')").fetchone()[0]
            if pending >= queue_limit:
                raise RuntimeFault('QUEUE_FULL', 'No durable admission was made; retry later.', True)
            job_id, now = uuid.uuid4().hex, utc_now()
            con.execute('''INSERT INTO jobs(id,owner,request_key,request_hash,state,
                        priority,spec_json,created,updated) VALUES(?,?,?,?,?,?,?,?,?)''',
                        (job_id, owner, request_key, request_hash, 'QUEUED', priority,
                         canonical(spec), now, now))
            self._event(con, job_id, 'ACCEPTED')
            row = con.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            return dict(row), True

    def get(self, job_id: str, owner: str | None = None) -> dict:
        with self.connection() as con:
            row = con.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
        if not row or (owner is not None and row['owner'] != owner):
            raise RuntimeFault('NOT_FOUND', 'Execution not found for this identity.')
        return dict(row)

    def jobs(self, states=None, limit=100, owner=None) -> list[dict]:
        clauses, args = [], []
        if states:
            clauses.append('state IN (%s)' % ','.join('?' for _ in states))
            args.extend(states)
        if owner is not None:
            clauses.append('owner=?'); args.append(owner)
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        args.append(min(max(1, limit), 1000))
        with self.connection() as con:
            # 'where' is assembled only from fixed clauses; all values remain bound parameters.
            rows = con.execute('SELECT * FROM jobs' + where + ' ORDER BY priority,created LIMIT ?', args).fetchall()  # nosec B608
        return [dict(row) for row in rows]

    def recent_jobs(self, owner, limit=30):
        if type(limit) is not int or not 1<=limit<=200:
            raise RuntimeFault('INVALID_LIMIT','Execution history limit must be 1..200.')
        with self.connection() as con:
            rows=con.execute('SELECT * FROM jobs WHERE owner=? ORDER BY rowid DESC LIMIT ?', (owner,limit)).fetchall()
        return [dict(row) for row in rows]

    def transition(self, job_id: str, expected: set[str], state: str, **fields) -> bool:
        allowed = {'runner_pid', 'runner_created', 'child_pid', 'exit_code', 'detail'}
        if set(fields) - allowed:
            raise ValueError('Unknown transition field')
        with self.connection(True) as con:
            row = con.execute('SELECT state FROM jobs WHERE id=?', (job_id,)).fetchone()
            if not row or row['state'] not in expected:
                return False
            assignments = ['state=?', 'updated=?'] + [k + '=?' for k in fields]
            # assignment identifiers are constrained by the fixed 'allowed' set above.
            con.execute('UPDATE jobs SET ' + ','.join(assignments) + ' WHERE id=?',  # nosec B608
                        [state, utc_now(), *fields.values(), job_id])
            self._event(con, job_id, state, fields)
        return True

    def cancel(self, job_id: str, owner: str) -> dict:
        with self.connection(True) as con:
            row = con.execute('SELECT * FROM jobs WHERE id=? AND owner=?', (job_id, owner)).fetchone()
            if not row:
                raise RuntimeFault('NOT_FOUND', 'Execution not found for this identity.')
            if row['state'] not in TERMINAL:
                con.execute('UPDATE jobs SET cancel_requested=1,updated=? WHERE id=?', (utc_now(), job_id))
                self._event(con, job_id, 'CANCEL_REQUESTED')
        return self.get(job_id, owner)

    def input(self, job_id: str, owner: str, text: str, request_key: str):
        if not request_key or len(request_key) > 128:
            raise RuntimeFault('INVALID_KEY', 'Input requires an idempotency key (max 128 chars).')
        if len(text.encode('utf-8')) > 65536:
            raise RuntimeFault('INPUT_TOO_LARGE', 'Input exceeds 64 KiB.')
        with self.connection(True) as con:
            row = con.execute('SELECT * FROM jobs WHERE id=? AND owner=?', (job_id, owner)).fetchone()
            if not row or row['state'] != 'RUNNING':
                raise RuntimeFault('NOT_RUNNING', 'Input requires a running execution.')
            existing = con.execute('SELECT text FROM inputs WHERE job_id=? AND request_key=?',
                                   (job_id, request_key)).fetchone()
            if existing and existing['text'] != text:
                raise RuntimeFault('IDEMPOTENCY_CONFLICT', 'Input key already used with different text.')
            if not existing and con.execute('SELECT count(*) FROM inputs WHERE job_id=? AND delivered=0', (job_id,)).fetchone()[0] >= 16:
                raise RuntimeFault('INPUT_QUEUE_FULL', 'Input queue is full.', True)
            con.execute('INSERT OR IGNORE INTO inputs(job_id,request_key,text) VALUES(?,?,?)',
                        (job_id, request_key, text))
        return {'accepted': True, 'delivery_guarantee': 'at-most-once attempt; inspect output after a runner crash'}

    def claim_inputs(self, job_id):
        # An idle stdin poll is read-only: no BEGIN IMMEDIATE/fsync on an empty queue.
        with self.connection() as probe:
            if not probe.execute('SELECT 1 FROM inputs WHERE job_id=? AND delivered=0 LIMIT 1',(job_id,)).fetchone():
                return []
        with self.connection(True) as con:
            rows = con.execute('SELECT sequence,text FROM inputs WHERE job_id=? AND delivered=0 ORDER BY sequence LIMIT 32',
                               (job_id,)).fetchall()
            for row in rows:
                con.execute('UPDATE inputs SET delivered=1 WHERE sequence=?', (row['sequence'],))
        return [dict(row) for row in rows]

    def audit(self, kind: str, data: dict):
        with self.connection() as con:
            self._event(con, None, kind, data)

    def summary(self, owner=None):
        with self.connection() as con:
            where,args=(' WHERE owner=?',(owner,)) if owner is not None else ('',())
            # 'where' is either empty or the fixed owner predicate above.
            rows = con.execute('SELECT state,count(*) n FROM jobs'+where+' GROUP BY state',args).fetchall()  # nosec B608
        return {r['state']: r['n'] for r in rows}

    def backup(self, destination: Path):
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as source:
            target = sqlite3.connect(destination)
            try:
                source.backup(target)
            finally:
                target.close()
