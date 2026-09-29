from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path

from .common import RuntimeFault, utc_now
from .filesystem import PathPolicy, FileSystem
from .coverage import WikiCoverage


class WikiIndex:
    """Derived local FTS index; the existing Wiki remains the authoritative source."""
    def __init__(self, root: Path, index: Path, manifest: Path | None = None):
        self.root, self.index, self.manifest = root.resolve(), index, manifest
        self.files = FileSystem(PathPolicy({'wiki':self.root}), index.parent)
        index.parent.mkdir(parents=True, exist_ok=True)
        con = self.connect()
        try:
            con.executescript('''PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS documents(path TEXT PRIMARY KEY,sha256 TEXT NOT NULL,
                    mtime_ns INTEGER NOT NULL,size INTEGER NOT NULL,indexed_at TEXT NOT NULL,body TEXT NOT NULL);
                CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(path UNINDEXED,body,tokenize='unicode61');
            ''')
            con.commit()
        finally:
            con.close()

        self.coverage = WikiCoverage(self.root, self.index)

    def connect(self):
        con = sqlite3.connect(self.index, timeout=2)
        con.row_factory = sqlite3.Row
        return con

    def refresh(self, max_documents=20000):
        if not self.root.is_dir():
            raise RuntimeFault('WIKI_MISSING', 'Configured Wiki root is unavailable.')
        if not 1 <= max_documents <= 20000:
            raise RuntimeFault('INVALID_LIMIT', 'Invalid index limit.')
        changed, skipped, seen, complete = 0, 0, set(), True
        con = self.connect()
        try:
            existing = {r['path']:dict(r) for r in con.execute('SELECT path,sha256,mtime_ns,size FROM documents')}
            for base, dirs, files in os.walk(self.root, followlinks=False):
                dirs[:] = [d for d in dirs if not d.startswith('.') and not (Path(base)/d).is_symlink()]
                for name in files:
                    if not name.lower().endswith(('.md','.mmd')):
                        continue
                    relative = (Path(base)/name).relative_to(self.root).as_posix()
                    if len(seen) >= max_documents:
                        complete = False; break
                    try:
                        path = self.files.policy.resolve('wiki', relative, True)
                        info = path.stat()
                        if info.st_size > 2*1024*1024:
                            skipped += 1; continue
                        seen.add(relative)
                        old = existing.get(relative)
                        if old and (old['mtime_ns'],old['size']) == (info.st_mtime_ns,info.st_size):
                            continue
                        raw = self.files._load(path)
                        content_hash = hashlib.sha256(raw).hexdigest()
                        body = raw.decode('utf-8-sig',errors='replace')
                        con.execute('INSERT OR REPLACE INTO documents VALUES(?,?,?,?,?,?)',
                                    (relative,content_hash,info.st_mtime_ns,info.st_size,utc_now(),body))
                        con.execute('DELETE FROM search WHERE path=?',(relative,))
                        con.execute('INSERT INTO search(path,body) VALUES(?,?)',(relative,body))
                        changed += 1
                        if changed % 50 == 0:
                            con.commit()
                    except (OSError, RuntimeFault):
                        skipped += 1
                if not complete:
                    break
            # Never interpret a partial/failed traversal as authoritative deletion.
            removed = 0
            if complete and not skipped:
                for path in set(existing)-seen:
                    con.execute('DELETE FROM documents WHERE path=?',(path,))
                    con.execute('DELETE FROM search WHERE path=?',(path,))
                    removed += 1
            con.commit()
            return {'changed':changed,'removed':removed,'seen':len(seen),'skipped':skipped,'complete':complete}
        finally:
            con.close()

    def refresh_paths(self, relative_paths, max_documents=128, max_seconds=10.0):
        """Refresh a bounded, explicit batch. Never infer deletions from a partial batch."""
        if not self.root.is_dir():
            raise RuntimeFault('WIKI_MISSING', 'Configured Wiki root is unavailable.')
        if (type(max_documents) is not int or not 1 <= max_documents <= 1000 or
                type(max_seconds) not in (int, float) or not 0 < max_seconds <= 60):
            raise RuntimeFault('INVALID_LIMIT', 'Invalid batch budget.')
        if not isinstance(relative_paths, (list, tuple)) or len(relative_paths) > 1000:
            raise RuntimeFault('INVALID_BATCH', 'An explicit batch of at most 1000 paths is required.')
        paths = list(dict.fromkeys(relative_paths))
        deadline = time.monotonic() + max_seconds
        processed, changed, skipped, source_races = 0, 0, 0, 0
        errors = []
        con = self.connect()
        try:
            for relative in paths:
                if processed >= max_documents or time.monotonic() >= deadline:
                    break
                processed += 1
                try:
                    if not isinstance(relative, str) or Path(relative).suffix.lower() not in {'.md', '.mmd'}:
                        raise RuntimeFault('INVALID_WIKI_PATH', 'Only Markdown and Mermaid files can be indexed.')
                    path = self.files.policy.resolve('wiki', relative, True)
                    key = path.relative_to(self.root).as_posix()
                    info = path.stat()
                    old = con.execute('SELECT sha256,mtime_ns,size FROM documents WHERE path=?', (key,)).fetchone()
                    if old and (old['mtime_ns'], old['size']) == (info.st_mtime_ns, info.st_size):
                        continue
                    raw = self.files._load(path)
                    after = path.stat()
                    if (info.st_mtime_ns, info.st_size) != (after.st_mtime_ns, after.st_size) or len(raw) != after.st_size:
                        source_races += 1
                        raise RuntimeFault('SOURCE_CHANGED', 'Source changed during reading; retry in a later batch.')
                    body = raw.decode('utf-8-sig', errors='replace')
                    con.execute('INSERT OR REPLACE INTO documents VALUES(?,?,?,?,?,?)',
                                (key, hashlib.sha256(raw).hexdigest(), after.st_mtime_ns, after.st_size, utc_now(), body))
                    con.execute('DELETE FROM search WHERE path=?', (key,))
                    con.execute('INSERT INTO search(path,body) VALUES(?,?)', (key, body))
                    con.commit()
                    changed += 1
                except (OSError, RuntimeFault) as exc:
                    skipped += 1
                    errors.append({'path': str(relative), 'error': getattr(exc, 'code', type(exc).__name__)})
            return {'mode': 'explicit_batch', 'requested': len(paths), 'processed': processed,
                    'changed': changed, 'removed': 0, 'skipped': skipped, 'source_races': source_races,
                    'complete': processed == len(paths) and skipped == 0,
                    'remaining': paths[processed:], 'errors': errors[:20],
                    'scope': 'selected_paths_only_not_full_wiki'}
        finally:
            con.close()

    def search(self, query, limit=10):
        tokens = re.findall(r'\w+', query, re.UNICODE)
        if not tokens or len(query) > 256 or not 1 <= limit <= 50:
            raise RuntimeFault('INVALID_QUERY','Invalid Wiki query or limit.')
        expression = ' AND '.join('"'+t+'"' for t in tokens[:12])
        con = self.connect()
        try:
            rows = con.execute('''SELECT search.path,snippet(search,1,'','',' … ',32) excerpt,
                d.sha256,d.indexed_at,d.mtime_ns FROM search JOIN documents d ON d.path=search.path
                WHERE search MATCH ? ORDER BY bm25(search) LIMIT ?''',(expression,limit)).fetchall()
        finally:
            con.close()
        result=[]
        for row in rows:
            entry=dict(row)
            entry['source_classification']='generated_candidate' if '/generated/' in row['path'] else 'authority_not_evaluated'
            try:
                entry['source_changed_since_index']=(self.root/row['path']).stat().st_mtime_ns != row['mtime_ns']
            except OSError:
                entry['source_changed_since_index']=True
            result.append(entry)
        return {'matches':result,'source_root':str(self.root),'index_is_derived':True,
                **self.coverage.status()}

    def read(self, path, offset=0, length=200):
        return self.files.read('wiki',path,offset,length)

    def status(self):
        con=self.connect()
        try:
            count=con.execute('SELECT count(*) FROM documents').fetchone()[0]
        finally:
            con.close()
        manifest = {}
        if self.manifest and self.manifest.is_file() and self.manifest.stat().st_size < 1024*1024:
            data=json.loads(self.manifest.read_text(encoding='utf-8-sig'))
            manifest={k:data.get(k) for k in ('schema_version','generated_at','module_page_count')}
        return {'root':str(self.root),'indexed_documents':count,'manifest':manifest,
                'automatic_regeneration_of_source':False,**self.coverage.status()}
