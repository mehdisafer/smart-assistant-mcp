from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def atomic_bytes(path: Path, content: bytes) -> None:
    """Replace on the same filesystem only after the new file has been flushed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        attempts=20 if os.name=='nt' else 1
        for attempt in range(attempts):
            try:
                os.replace(name, path)
                break
            except PermissionError:
                if attempt+1>=attempts: raise
                import time
                time.sleep(min(.05,.005*(attempt+1)))
    finally:
        if os.path.exists(name):
            os.unlink(name)


def atomic_json(path: Path, value: Any) -> None:
    atomic_bytes(path, (canonical(value) + '\n').encode('utf-8'))


class RuntimeFault(Exception):
    def __init__(self, code: str, message: str, retryable: bool = False):
        super().__init__(message)
        self.code, self.retryable = code, retryable

    def as_dict(self) -> dict:
        return {'error': self.code, 'message': str(self), 'retryable': self.retryable}


def exception_code(exc):
    """Flatten exception groups using type/code only; never copy external message text."""
    import asyncio,re
    if isinstance(exc,RuntimeFault):return exc.code
    if isinstance(exc,BaseExceptionGroup):
        codes=[exception_code(e) for e in exc.exceptions]
        preferred=[c for c in codes if c not in {'BACKEND_FAILURE','CANCELLED'}]
        return preferred[0] if preferred else 'BACKEND_FAILURE'
    if isinstance(exc,PermissionError) or getattr(exc,'winerror',None)==5:return 'ACCESS_DENIED'
    if isinstance(exc,FileNotFoundError):return 'NOT_FOUND'
    if isinstance(exc,TimeoutError):return 'TIMEOUT'
    if isinstance(exc,asyncio.CancelledError):return 'CANCELLED'
    if getattr(exc,'code',None) and re.fullmatch(r'[A-Z][A-Z0-9_]{1,63}',str(exc.code)):return str(exc.code)
    return 'BACKEND_FAILURE'
