"""Persist a qualified inventory snapshot; never claim that source documentation is current."""
import hashlib, json, math, sqlite3, time
from pathlib import Path, PurePosixPath
from .common import RuntimeFault, utc_now

class WikiCoverage:
    def __init__(self, root, index):
        self.root, self.index = Path(root).resolve(), Path(index)
        con=self.connect()
        try:
            con.execute("CREATE TABLE IF NOT EXISTS coverage_proof(id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL)")
            for table in ('documents','search'):
                if table=='search':
                    # FTS5 virtual tables cannot carry triggers; validate their counts at qualification.
                    continue
                for operation in ('INSERT','UPDATE','DELETE'):
                    # table/operation come only from the closed constant tuples above.
                    con.execute(f"CREATE TRIGGER IF NOT EXISTS invalidate_coverage_{table}_{operation.lower()} AFTER {operation} ON {table} BEGIN DELETE FROM coverage_proof; END")  # nosec B608
            con.commit()
        finally: con.close()

    def connect(self):
        return sqlite3.connect(self.index, timeout=3)

    def qualify(self, inventory):
        if (inventory.get('complete') is not True or inventory.get('inventory_complete') is not True
                or inventory.get('errors') or inventory.get('inventory_errors') or inventory.get('inventory_pending')):
            raise RuntimeFault('INCOMPLETE_INVENTORY','Inventory is incomplete or contains errors.')
        if Path(inventory.get('source','')).resolve()!=self.root:
            raise RuntimeFault('INVENTORY_ROOT_MISMATCH','Inventory does not describe this Wiki.')
        paths=inventory.get('paths')
        if not isinstance(paths,list) or not paths or len(paths)>20000 or any(not isinstance(p,str) for p in paths):
            raise RuntimeFault('INVALID_INVENTORY','Expected a nonempty bounded inventory.')
        if len(paths)!=len(set(paths)) or inventory.get('offset')!=len(paths):
            raise RuntimeFault('INCOMPLETE_INVENTORY','Paths are duplicated or indexing has not completed.')
        for p in paths:
            q=PurePosixPath(p)
            if q.is_absolute() or '..' in q.parts or ':' in p or '\\' in p or q.suffix.lower() not in {'.md','.mmd'}:
                raise RuntimeFault('INVALID_INVENTORY_PATH','Inventory contains an unsafe or unsupported path.')
        at=inventory.get('inventory_at')
        if type(at) not in (float,int) or not math.isfinite(at) or at<=0 or at>time.time()+60:
            raise RuntimeFault('INVALID_INVENTORY_TIME','Inventory time is missing or invalid.')
        con=self.connect()
        try:
            con.execute('BEGIN IMMEDIATE')
            rows=con.execute('SELECT path,sha256 FROM documents ORDER BY path').fetchall()
            search=con.execute('SELECT path,count(*) FROM search GROUP BY path').fetchall()
            actual={r[0] for r in rows}; expected=set(paths)
            if actual!=expected or {r[0] for r in search}!=expected or any(r[1]!=1 for r in search):
                raise RuntimeFault('INDEX_COVERAGE_MISMATCH','Index and completed inventory do not reconcile.')
            proof={'verified_at':utc_now(),'inventory_at':at,'source_root':str(self.root),
                   'scope':'nonhidden_markdown_mermaid_inventory_snapshot','document_count':len(rows),
                   'inventory_sha256':hashlib.sha256(json.dumps(sorted(paths),ensure_ascii=True).encode()).hexdigest(),
                   'index_content_sha256':hashlib.sha256(json.dumps(rows,ensure_ascii=True).encode()).hexdigest()}
            con.execute('INSERT OR REPLACE INTO coverage_proof(id,payload) VALUES(1,?)',(json.dumps(proof),))
            con.commit(); return proof
        finally: con.close()

    def status(self):
        con=self.connect()
        try:
            row=con.execute('SELECT payload FROM coverage_proof WHERE id=1').fetchone()
            count=con.execute('SELECT count(*) FROM documents').fetchone()[0]
        finally: con.close()
        proof=json.loads(row[0]) if row else None
        valid=bool(proof and proof.get('source_root')==str(self.root) and proof.get('document_count')==count)
        return {'coverage':'VERIFIED_INVENTORY_SNAPSHOT' if valid else 'UNQUALIFIED_OR_INDEX_CHANGED',
                'full_index_verified':valid,'coverage_proof':proof if valid else None,
                'current_source_completeness_verified':False,'documentation_freshness_verified':False}
