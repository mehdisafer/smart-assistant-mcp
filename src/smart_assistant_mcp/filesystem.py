from __future__ import annotations

import hashlib
import os
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from .common import RuntimeFault, atomic_bytes

DENIED_PARTS = {'.ssh', '.aws', '.azure', '.secrets', 'credentials', 'secrets', '.git', '.env'}


class PathPolicy:
    """Application path policy, NOT a sandbox for arbitrary shell commands."""
    def __init__(self, roots: dict[str, str | Path], immutable_subpaths: dict[str, list[str]] | None=None):
        self.roots = {name: Path(value).resolve() for name, value in roots.items()}
        self.protected_stores = set()
        self.immutable_subpaths = {}
        for project, values in (immutable_subpaths or {}).items():
            if project not in self.roots:
                raise ValueError('immutable_subpaths references an unknown project: '+project)
            normalized=[]
            for value in values:
                if not isinstance(value,str) or not value.strip():
                    raise ValueError('immutable_subpaths entries must be nonempty relative paths')
                raw=value.replace('\\','/').strip('/')
                parts=tuple(p.casefold() for p in raw.split('/') if p)
                if not parts or any(p in {'.','..'} or ':' in p for p in parts):
                    raise ValueError('immutable_subpaths contains an unsafe path')
                normalized.append(parts)
            self.immutable_subpaths[project]=tuple(normalized)

    def resolve(self, project: str, relative: str, must_exist=False) -> Path:
        if project not in self.roots:
            raise RuntimeFault('UNKNOWN_PROJECT', 'Project is not registered.')
        if '\x00' in relative or ':' in relative or relative.startswith(('\\', '/')):
            raise RuntimeFault('INVALID_PATH', 'Only relative filesystem paths are accepted.')
        parts = relative.replace('\\', '/').split('/')
        if any(p == '..' or p.casefold() in DENIED_PARTS or p.casefold().startswith('.env') for p in parts):
            raise RuntimeFault('PATH_DENIED', 'Parent traversal or protected path.')
        for part in parts:
            stem = part.split('.')[0].upper()
            if part.endswith((' ', '.')) or stem in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}:
                raise RuntimeFault('PATH_DENIED', 'Ambiguous Windows path component.')
        root = self.roots[project]
        candidate = root.joinpath(*parts)
        resolved = candidate.resolve()
        if not resolved.is_relative_to(root):
            raise RuntimeFault('PATH_ESCAPE', 'Path escapes the registered root.')
        current = root
        for part in parts:
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise RuntimeFault('REPARSE_POINT', 'Symlinks and reparse points are not admitted.')
        if must_exist and not resolved.exists():
            raise RuntimeFault('NOT_FOUND', 'Path does not exist.')
        return resolved

    def resolve_mutation(self, project: str, relative: str, must_exist=False) -> Path:
        resolved=self.resolve(project,relative,must_exist)
        root=self.roots[project]
        parts=tuple(p.casefold() for p in resolved.relative_to(root).parts)
        for prefix in self.immutable_subpaths.get(project,()):
            if parts[:len(prefix)]==prefix:
                raise RuntimeFault('IMMUTABLE_PATH',
                    'This registered subpath is read-only by policy; use the governed promotion/packaging workflow.')
        return resolved


    def protected_roots(self) -> set[Path]:
        """Protected descendants are not movable via their writable ancestors."""
        return {
            *self.protected_stores,
            *(self.roots[project].joinpath(*prefix).resolve()
              for project, prefixes in self.immutable_subpaths.items()
              for prefix in prefixes),
        }

    def require_movable_tree(self, path: Path, *, limit: int = 4096) -> None:
        """Reject a directory move containing protected paths, names or reparse points."""
        if not path.is_dir():
            return
        if any(protected.is_relative_to(path) for protected in self.protected_roots()):
            raise RuntimeFault('IMMUTABLE_PATH', 'Move would relocate protected application data.')
        pending, examined = [path], 0
        while pending:
            directory = pending.pop()
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise RuntimeFault('REPARSE_POINT', 'A movable tree cannot contain reparse points.')
            with os.scandir(directory) as entries:
                for entry in entries:
                    examined += 1
                    if examined > limit:
                        raise RuntimeFault('PROTECTED_TREE_SCAN_BOUND',
                                           'Protected descendant inventory exceeds its limit.')
                    name = entry.name.casefold()
                    if name in DENIED_PARTS or name.startswith('.env'):
                        raise RuntimeFault('PROTECTED_MUTATION_PATH',
                                           'Move would relocate protected file names.')
                    details = entry.stat(follow_symlinks=False)
                    if (stat.S_ISLNK(details.st_mode) or
                            getattr(details, 'st_file_attributes', 0) & 0x400):
                        raise RuntimeFault('REPARSE_POINT', 'Move would relocate a reparse point.')
                    if stat.S_ISDIR(details.st_mode):
                        pending.append(Path(entry.path))

    @contextmanager
    def open_project_file(self, project: str, relative: str):
        """Validate the *opened handle* before a search reads any bytes.

        Path-only prechecks can race against an external filesystem writer.
        This does not isolate arbitrary executables launched by the MCP.
        """
        path = self.resolve(project, relative, True)
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or
                    getattr(opened, 'st_file_attributes', 0) & 0x400):
                raise RuntimeFault('NOT_REGULAR_FILE', 'Only regular non-reparse files are readable.')
            current = self.resolve(project, relative, True)
            actual = current.lstat()
            if (current != path or (opened.st_dev, opened.st_ino) !=
                    (actual.st_dev, actual.st_ino)):
                raise RuntimeFault('PATH_CHANGED', 'File identity changed during admission.')
            if os.name == 'nt':
                # Handle identity defeats a swapped ancestor junction between check and open.
                import ctypes
                import msvcrt
                from ctypes import wintypes
                api = ctypes.WinDLL('kernel32', use_last_error=True)
                get_name = api.GetFinalPathNameByHandleW
                get_name.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                    wintypes.DWORD, wintypes.DWORD]
                get_name.restype = wintypes.DWORD
                handle = msvcrt.get_osfhandle(fd)
                size = get_name(handle, None, 0, 0)
                if not size or size > 32767:
                    raise RuntimeFault('HANDLE_PATH_UNVERIFIED', 'Cannot verify opened file location.')
                buffer = ctypes.create_unicode_buffer(size + 1)
                count = get_name(handle, buffer, len(buffer), 0)
                if not count or count >= len(buffer):
                    raise RuntimeFault('HANDLE_PATH_UNVERIFIED', 'Cannot verify opened file location.')
                native = buffer.value
                marker = chr(92) * 2 + '?' + chr(92)
                if native.startswith(marker + 'UNC' + chr(92)):
                    absolute = chr(92) * 2 + native[len(marker) + 4:]
                elif native.startswith(marker):
                    absolute = native[len(marker):]
                else:
                    raise RuntimeFault('HANDLE_PATH_UNVERIFIED', 'Unknown opened path format.')
                if Path(absolute) != path:
                    raise RuntimeFault('PATH_CHANGED', 'Opened file escaped or moved from expected path.')
            with os.fdopen(fd, 'rb') as stream:
                fd = None
                yield stream
        finally:
            if fd is not None:
                os.close(fd)

class FileLock:
    """Cross-process writer lock.

    Windows uses an exclusive CreateFileW handle (share mode 0) instead of CRT
    byte-range locking. A stale lock file is harmless once its OS handle closes.
    """
    def __init__(self, path: Path):
        self.path, self.handle = path, None
        self.kernel = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == 'nt':
            import ctypes as c
            from ctypes import wintypes as w
            kernel=c.WinDLL('kernel32',use_last_error=True)
            kernel.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE]
            kernel.CreateFileW.restype=w.HANDLE
            kernel.CloseHandle.argtypes=[w.HANDLE]
            kernel.CloseHandle.restype=w.BOOL
            GENERIC_READ=0x80000000
            GENERIC_WRITE=0x40000000
            OPEN_ALWAYS=4
            FILE_ATTRIBUTE_NORMAL=0x80
            handle=kernel.CreateFileW(str(self.path),GENERIC_READ|GENERIC_WRITE,0,None,
                                      OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,None)
            invalid=c.c_void_p(-1).value
            if handle in (None,0,invalid):
                code=c.get_last_error()
                if code in {32,33}:
                    raise RuntimeFault('RESOURCE_LOCKED','Another writer owns this resource.',True)
                if code==5:
                    raise RuntimeFault('ACCESS_DENIED','Writer lock path is not accessible.')
                raise RuntimeFault('LOCK_OPEN_FAILED','Writer lock could not be opened.',True)
            self.handle,self.kernel=handle,kernel
            return self
        self.handle=self.path.open('a+b')
        try:
            import fcntl
            fcntl.flock(self.handle.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            self.handle.close();self.handle=None
            raise RuntimeFault('RESOURCE_LOCKED','Another writer owns this resource.',True)
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.handle:
            return False
        handle=self.handle
        self.handle=None
        if os.name=='nt':
            kernel=self.kernel
            self.kernel=None
            if not kernel.CloseHandle(handle) and exc_type is None:
                raise RuntimeFault('LOCK_RELEASE_FAILED','Writer lock handle could not be closed.')
            return False
        try:
            import fcntl
            fcntl.flock(handle.fileno(),fcntl.LOCK_UN)
        finally:
            handle.close()
        return False


class FileSystem:
    def __init__(self, policy: PathPolicy, state_dir: Path, max_file_bytes=2*1024*1024):
        self.policy, self.state_dir, self.max_file_bytes = policy, state_dir, max_file_bytes
        self.policy.protected_stores.add(Path(state_dir).resolve())

    def _load(self, path):
        if not path.is_file():
            raise RuntimeFault('NOT_FILE', 'A regular file is required.')
        with path.open('rb') as f:
            raw = f.read(self.max_file_bytes + 1)
        if len(raw) > self.max_file_bytes:
            raise RuntimeFault('FILE_TOO_LARGE', 'Use a bounded streaming job for this file.')
        if b'\x00' in raw:
            raise RuntimeFault('BINARY_FILE', 'This tool accepts text; use a dedicated binary-format adapter.')
        return raw

    def read(self, project, relative, offset=0, length=200):
        if not 0 <= offset <= 1_000_000 or not 1 <= length <= 1000:
            raise RuntimeFault('INVALID_RANGE', 'Line offset or length is out of range.')
        path = self.policy.resolve(project, relative, True)
        raw = self._load(path)
        lines = raw.decode('utf-8-sig', errors='replace').splitlines()
        text = '\n'.join(lines[offset:offset + length])
        return {'project': project, 'path': relative, 'sha256': hashlib.sha256(raw).hexdigest(),
                'offset': offset, 'total_lines': len(lines), 'content': text[:65536],
                'truncated': len(text) > 65536 or offset + length < len(lines)}

    def list(self, project, relative='', limit=100):
        if not 1 <= limit <= 500:
            raise RuntimeFault('INVALID_LIMIT', 'Limit must be between 1 and 500.')
        path = self.policy.resolve(project, relative, True)
        if not path.is_dir():
            raise RuntimeFault('NOT_DIRECTORY', 'Directory required.')
        out = []
        with os.scandir(path) as entries:
            for entry in entries:
                if entry.name.casefold() in DENIED_PARTS or entry.name.casefold().startswith('.env'):
                    continue
                out.append({'name':entry.name, 'directory':entry.is_dir(follow_symlinks=False)})
                if len(out) > limit:
                    break
        return {'entries':out[:limit], 'truncated':len(out) > limit}

    @staticmethod
    def _prepare_target(path: Path, raw: bytes) -> Path:
        """Durably stage bytes on the target filesystem before acquiring the writer lock.

        Use a small, bounded O_EXCL loop instead of tempfile.mkstemp. On Windows,
        mkstemp may retry many candidate names after ACCESS_DENIED on an existing
        read-only directory, turning a simple ACL denial into a long hang.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_BINARY',0)
        staged=None; fd=None
        for _ in range(4):
            candidate=path.parent/('.'+path.name+'.stage.'+os.urandom(8).hex())
            try:
                fd=os.open(candidate,flags,0o600)
                staged=candidate
                break
            except FileExistsError:
                continue
        if staged is None or fd is None:
            raise RuntimeFault('TEMP_STAGE_COLLISION','Could not allocate a unique staging file.',True)
        try:
            with os.fdopen(fd,'wb') as handle:
                fd=None
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            return staged
        except BaseException:
            if fd is not None:
                try: os.close(fd)
                except OSError: pass
            try:
                staged.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    def write(self, project, relative, content, expected_sha256):
        raw = content.encode('utf-8')
        if len(raw) > self.max_file_bytes:
            raise RuntimeFault('FILE_TOO_LARGE', 'Write exceeds configured bound.')
        path = self.policy.resolve_mutation(project, relative)
        resource = hashlib.sha256(str(path).casefold().encode()).hexdigest()
        staged = None
        previous = None
        actual = None
        pre_actual = 'CREATE'
        backup_path = None
        try:
            # All potentially slow fsync work happens before the target lock.
            staged = self._prepare_target(path, raw)
            if path.exists():
                pre_previous = self._load(path)
                pre_actual = hashlib.sha256(pre_previous).hexdigest()
                if pre_actual == expected_sha256:
                    backup_path = self.state_dir/'file-backups'/(resource + '-' + pre_actual)
                    if not backup_path.exists():
                        atomic_bytes(backup_path, pre_previous)

            with FileLock(self.state_dir/'locks'/resource):
                previous = self._load(path) if path.exists() else None
                actual = hashlib.sha256(previous).hexdigest() if previous is not None else 'CREATE'
                # Conservative ABA protection: if the pre-lock observation did not match the
                # caller's expected version, do not accept a later return to the same hash.
                if actual != expected_sha256 or pre_actual != expected_sha256:
                    raise RuntimeFault('VERSION_CONFLICT', 'File changed since the read, or CREATE was not specified.')
                # Existing versions are already durably backed up before the lock is acquired.
                if previous is not None and (backup_path is None or not backup_path.is_file()):
                    raise RuntimeFault('BACKUP_NOT_READY', 'Previous version backup is not durably staged.', True)
                os.replace(staged, path)
                staged = None
        except PermissionError as exc:
            raise RuntimeFault('ACCESS_DENIED', 'Service account cannot write this target path.') from exc
        finally:
            if staged is not None:
                try:
                    staged.unlink(missing_ok=True)
                except OSError:
                    pass
        return {'path':relative, 'sha256':hashlib.sha256(raw).hexdigest(), 'previous_sha256':actual,
                'bytes':len(raw), 'backup_preserved':previous is not None}

    def search(self, project, query, limit=20):
        if not query or len(query) > 256 or not 1 <= limit <= 100:
            raise RuntimeFault('INVALID_QUERY', 'Query and result limit are out of bounds.')
        if project not in self.policy.roots:
            raise RuntimeFault('UNKNOWN_PROJECT', 'Project is not registered.')
        root = self.policy.roots[project]
        deadline, bytes_read, examined, results = time.monotonic()+2, 0, 0, []
        bounded = False
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d.casefold() not in DENIED_PARTS and d not in
                       {'.venv','node_modules','runtime','runtimes','data','backups','.pytest_cache','__pycache__'}]
            for name in files:
                if time.monotonic() > deadline or bytes_read >= 16*1024*1024 or examined >= 1000:
                    bounded = True; break
                relative = str((Path(base)/name).relative_to(root))
                try:
                    path = self.policy.resolve(project, relative, True)
                    if path.suffix.lower() not in {'.md','.mmd','.py','.js','.ts','.json','.yaml','.yml','.toml','.txt','.ps1'}:
                        continue
                    raw = self._load(path)
                except (OSError, RuntimeFault):
                    continue
                examined += 1; bytes_read += len(raw)
                for line_number, line in enumerate(raw.decode('utf-8',errors='replace').splitlines(), 1):
                    if query.casefold() in line.casefold():
                        results.append({'path':relative,'line':line_number,'text':line[:500]})
                        if len(results) >= limit:
                            bounded = True; break
                if bounded:
                    break
            if bounded:
                break
        return {'matches':results,'partial':bounded,'files_examined':examined,'bytes_read':bytes_read}