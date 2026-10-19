from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
import threading
import time
import uuid
from pathlib import Path

from .common import RuntimeFault, atomic_json, utc_now
from .filesystem import DENIED_PARTS, PathPolicy


class SearchManager:
    """Durable bounded searches. Results survive HTTP reconnects and completed sessions survive service restarts."""

    def __init__(self, policy: PathPolicy, state_dir: Path, governor):
        self.policy = policy
        self.root = Path(state_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.governor = governor
        self.lock = threading.RLock()
        self.active: dict[str, tuple[threading.Thread, threading.Event]] = {}
        self._repair_interrupted()

    def _repair_interrupted(self):
        for meta_path in self.root.glob("*/meta.json"):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8-sig"))
                if meta.get("status") in {"QUEUED", "RUNNING"}:
                    meta["status"] = "INTERRUPTED"
                    meta["finished_at"] = utc_now()
                    meta["detail"] = "service_restart_or_worker_loss"
                    atomic_json(meta_path, meta)
            except Exception:
                continue

    @staticmethod
    def _validate_session_id(session_id: str):
        if not isinstance(session_id, str) or not re.fullmatch(r"search_[0-9a-f]{32}", session_id):
            raise RuntimeFault("INVALID_SEARCH_ID", "Invalid search session identifier.")

    def _folder(self, session_id: str) -> Path:
        self._validate_session_id(session_id)
        return self.root / session_id

    def _write_meta(self, session_id: str, meta: dict):
        with self.lock:
            atomic_json(self._folder(session_id) / "meta.json", meta)

    def _meta(self, session_id: str) -> dict:
        path = self._folder(session_id) / "meta.json"
        with self.lock:
            if not path.is_file():
                raise RuntimeFault("SEARCH_NOT_FOUND", "Search session does not exist.")
            try:
                return json.loads(path.read_text(encoding="utf-8-sig"))
            except Exception as exc:
                raise RuntimeFault("SEARCH_STATE_INVALID", "Search metadata is invalid.") from exc

    @staticmethod
    def _authorize(meta: dict, owner: str, project: str | None = None):
        if meta.get("owner") != owner or (project is not None and meta.get("project") != project):
            raise RuntimeFault("SEARCH_DENIED", "Search session belongs to another identity or project.")

    def start(self, owner: str, project: str, relative_path: str, pattern: str,
              search_type: str = "content", file_pattern: str | None = None,
              ignore_case: bool = True, max_results: int = 200,
              include_hidden: bool = False, context_lines: int = 2,
              timeout_seconds: float = 30.0, literal: bool = False) -> dict:
        if search_type not in {"files", "content"}:
            raise RuntimeFault("INVALID_SEARCH_TYPE", "search_type must be files or content.")
        if not isinstance(pattern, str) or not pattern or len(pattern) > 512:
            raise RuntimeFault("INVALID_PATTERN", "Search pattern is empty or too long.")
        if type(max_results) is not int or not 1 <= max_results <= 2000:
            raise RuntimeFault("INVALID_LIMIT", "max_results must be between 1 and 2000.")
        if type(context_lines) is not int or not 0 <= context_lines <= 8:
            raise RuntimeFault("INVALID_CONTEXT", "context_lines must be between 0 and 8.")
        if type(timeout_seconds) not in (int, float) or not 1 <= timeout_seconds <= 120:
            raise RuntimeFault("INVALID_TIMEOUT", "Search timeout must be between 1 and 120 seconds.")
        target = self.policy.resolve(project, relative_path, True)
        if not (target.is_dir() or target.is_file()):
            raise RuntimeFault("INVALID_SEARCH_ROOT", "Search root must be a file or directory.")

        with self.lock:
            active_owner = 0
            for sid, (thread, _) in list(self.active.items()):
                if not thread.is_alive():
                    self.active.pop(sid, None)
                    continue
                try:
                    if self._meta(sid).get("owner") == owner:
                        active_owner += 1
                except RuntimeFault:
                    pass
            if len(self.active) >= 8 or active_owner >= 4:
                raise RuntimeFault("SEARCH_CONCURRENCY_LIMIT", "Too many active searches.", True)

            session_id = "search_" + uuid.uuid4().hex
            lease_key = "search:" + session_id
            self.governor.acquire(lease_key, .08, 1, False, "L1")
            folder = self._folder(session_id)
            folder.mkdir(parents=True, exist_ok=False)
            meta = {
                "id": session_id, "owner": owner, "project": project,
                "relative_path": relative_path, "pattern": pattern, "search_type": search_type,
                "file_pattern": file_pattern, "ignore_case": bool(ignore_case),
                "max_results": max_results, "include_hidden": bool(include_hidden),
                "context_lines": context_lines, "timeout_seconds": float(timeout_seconds),
                "literal": bool(literal), "status": "QUEUED", "created_at": utc_now(),
                "result_count": 0, "files_examined": 0, "bytes_read": 0, "partial": False,
            }
            self._write_meta(session_id, meta)
            stop = threading.Event()
            thread = threading.Thread(
                target=self._run,
                args=(session_id, target, meta, stop, lease_key),
                name=session_id, daemon=True)
            self.active[session_id] = (thread, stop)
            thread.start()
            return self.public(meta)

    def _iter_files(self, project: str, target: Path, include_hidden: bool):
        """Yield only regular files admitted by the policy used for direct reads."""
        root = self.policy.roots[project]

        def checked(path: Path, directory: bool):
            try:
                relative = path.relative_to(root).as_posix()
                # pathlib represents the project root as '.', which the path
                # policy correctly rejects as a user-supplied component.
                if relative == '.':
                    relative = ''
                admitted = self.policy.resolve(project, relative, True)
                info = admitted.lstat()
                if (stat.S_ISLNK(info.st_mode) or
                        getattr(info, 'st_file_attributes', 0) & 0x400):
                    return None
                expected = stat.S_ISDIR if directory else stat.S_ISREG
                return admitted if expected(info.st_mode) else None
            except (OSError, ValueError, RuntimeFault):
                return None

        if target.is_file():
            admitted = checked(target, False)
            if admitted is not None:
                yield admitted
            return

        skipped = {'.venv', 'node_modules', '__pycache__', '.pytest_cache'}
        for base, dirs, files in os.walk(target, followlinks=False):
            if checked(Path(base), True) is None:
                dirs[:] = []
                continue
            dirs[:] = sorted(
                d for d in dirs
                if (include_hidden or not d.startswith('.'))
                and d not in skipped
                and checked(Path(base) / d, True) is not None
            )
            for name in sorted(files):
                if not include_hidden and name.startswith('.'):
                    continue
                admitted = checked(Path(base) / name, False)
                if admitted is not None:
                    yield admitted

    def _run(self, session_id: str, target: Path, meta: dict,
             stop: threading.Event, lease_key: str):
        folder = self._folder(session_id)
        results_path = folder / "results.jsonl"
        started = time.monotonic()
        flags = re.IGNORECASE if meta["ignore_case"] else 0
        matcher = None
        if meta["search_type"] == "content" and not meta["literal"]:
            try:
                matcher = re.compile(meta["pattern"], flags)
            except re.error as exc:
                meta["status"] = "FAILED"; meta["detail"] = "invalid_regex: " + str(exc)[:160]
                meta["finished_at"] = utc_now(); self._write_meta(session_id, meta)
                self.governor.release(lease_key)
                return

        def matched(text: str) -> bool:
            if meta["search_type"] == "files" and not meta["literal"]:
                left=text.casefold() if meta["ignore_case"] else text
                right=meta["pattern"].casefold() if meta["ignore_case"] else meta["pattern"]
                return fnmatch.fnmatchcase(left,right)
            if meta["literal"]:
                return meta["pattern"].casefold() in text.casefold() if meta["ignore_case"] else meta["pattern"] in text
            return matcher.search(text) is not None

        try:
            meta["status"] = "RUNNING"; meta["started_at"] = utc_now()
            self._write_meta(session_id, meta)
            with results_path.open("a", encoding="utf-8", buffering=1) as out:
                for path in self._iter_files(meta["project"], target, meta["include_hidden"]):
                    if stop.is_set():
                        meta["status"] = "STOPPED"; break
                    if time.monotonic() - started >= meta["timeout_seconds"]:
                        meta["status"] = "TIMEOUT"; meta["partial"] = True; break
                    if meta["files_examined"] >= 50000 or meta["bytes_read"] >= 256 * 1024 * 1024:
                        meta["status"] = "BOUNDED"; meta["partial"] = True; break
                    try:
                        relative = path.relative_to(self.policy.roots[meta["project"]]).as_posix()
                    except ValueError:
                        continue
                    if meta["file_pattern"] and not fnmatch.fnmatch(path.name, meta["file_pattern"]):
                        continue
                    if meta["search_type"] == "files":
                        meta["files_examined"] += 1
                        if matched(path.name):
                            out.write(json.dumps({"path": relative}, ensure_ascii=False) + "\n")
                            meta["result_count"] += 1
                    else:
                        try:
                            # Iterator path checks are not authorization to open later.
                            with self.policy.open_project_file(meta["project"], relative) as stream:
                                raw = stream.read(4 * 1024 * 1024 + 1)
                            if len(raw) > 4 * 1024 * 1024:
                                continue
                            meta["bytes_read"] += len(raw); meta["files_examined"] += 1
                            if b"\x00" in raw:
                                continue
                            lines = raw.decode("utf-8-sig", errors="replace").splitlines()
                        except (OSError, RuntimeFault):
                            continue
                        for index, line in enumerate(lines):
                            if matched(line):
                                c = meta["context_lines"]
                                out.write(json.dumps({
                                    "path": relative, "line": index + 1, "text": line[:1000],
                                    "before": lines[max(0, index-c):index],
                                    "after": lines[index+1:index+1+c],
                                }, ensure_ascii=False) + "\n")
                                meta["result_count"] += 1
                                if meta["result_count"] >= meta["max_results"]:
                                    meta["status"] = "COMPLETED"; meta["partial"] = True
                                    break
                        if meta["result_count"] >= meta["max_results"]:
                            break
                    if meta["result_count"] >= meta["max_results"]:
                        meta["status"] = "COMPLETED"; meta["partial"] = True; break
                    if meta["files_examined"] % 50 == 0:
                        self._write_meta(session_id, meta)
                else:
                    if meta["status"] == "RUNNING":
                        meta["status"] = "COMPLETED"
        except Exception as exc:
            meta["status"] = "FAILED"; meta["detail"] = type(exc).__name__ + ": " + str(exc)[:200]
        finally:
            meta["finished_at"] = utc_now()
            meta["elapsed_seconds"] = round(time.monotonic() - started, 3)
            self._write_meta(session_id, meta)
            self.governor.release(lease_key)
            with self.lock:
                self.active.pop(session_id, None)

    @staticmethod
    def public(meta: dict) -> dict:
        return {k: meta.get(k) for k in (
            "id","project","relative_path","pattern","search_type","status","created_at",
            "started_at","finished_at","elapsed_seconds","result_count","files_examined",
            "bytes_read","partial","detail"
        ) if k in meta}

    def results(self, owner: str, session_id: str, offset: int = 0, length: int = 100) -> dict:
        if type(offset) is not int or offset < 0 or type(length) is not int or not 1 <= length <= 500:
            raise RuntimeFault("INVALID_RANGE", "Invalid result offset or length.")
        meta = self._meta(session_id); self._authorize(meta, owner)
        rows = []
        path = self._folder(session_id) / "results.jsonl"
        if path.is_file():
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for index, line in enumerate(handle):
                    if index < offset: continue
                    if len(rows) >= length: break
                    try: rows.append(json.loads(line))
                    except json.JSONDecodeError: continue
        return {"session": self.public(meta), "offset": offset,
                "next_offset": offset + len(rows), "results": rows}

    def stop(self, owner: str, session_id: str) -> dict:
        meta = self._meta(session_id); self._authorize(meta, owner)
        with self.lock:
            pair = self.active.get(session_id)
            if pair:
                pair[1].set()
                return {"id": session_id, "stop_requested": True, "status": meta.get("status")}
        return {"id": session_id, "stop_requested": False, "status": meta.get("status")}

    def list(self, owner: str, limit: int = 50) -> dict:
        if type(limit) is not int or not 1 <= limit <= 200:
            raise RuntimeFault("INVALID_LIMIT", "limit must be between 1 and 200.")
        rows = []
        for path in self.root.glob("*/meta.json"):
            try:
                meta = json.loads(path.read_text(encoding="utf-8-sig"))
                if meta.get("owner") == owner:
                    rows.append(meta)
            except Exception:
                continue
        rows.sort(key=lambda x: x.get("created_at",""), reverse=True)
        return {"searches": [self.public(x) for x in rows[:limit]], "truncated": len(rows) > limit}
