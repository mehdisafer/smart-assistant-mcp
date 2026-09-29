from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from pathlib import Path


class IdentityRegistry:
    def __init__(self, path: Path):
        self.path=path
        self.records=[]
        self.loaded_at=float('-inf')

    def verify(self, token: str) -> dict | None:
        if not isinstance(token,str) or not token or len(token)>4096: return None
        if time.monotonic()-self.loaded_at>2:
            # A missing or malformed registry fails closed, including during rotation.
            self.records=[]
            try:
                data=json.loads(self.path.read_text(encoding='utf-8-sig'))
                records=data['identities']
                if not isinstance(records,list): return None
                for record in records:
                    if not isinstance(record,dict): return None
                    if not isinstance(record.get('owner'),str) or not record['owner']: return None
                    if not isinstance(record.get('sha256'),str) or not re.fullmatch('[0-9a-f]{64}',record['sha256']): return None
                    if type(record.get('expires_at')) not in (int,float) or not math.isfinite(record['expires_at']): return None
                    if not isinstance(record.get('scopes'),list) or any(not isinstance(x,str) for x in record['scopes']): return None
                self.records=records
            except (OSError,ValueError,KeyError,TypeError):
                return None
            self.loaded_at=time.monotonic()
        value=hashlib.sha256(token.encode()).hexdigest()
        for record in self.records:
            if record.get('revoked') or record.get('expires_at',0)<=time.time(): continue
            if hmac.compare_digest(value,record.get('sha256','')):
                return {k:record[k] for k in ('owner','scopes','expires_at')}
        return None
