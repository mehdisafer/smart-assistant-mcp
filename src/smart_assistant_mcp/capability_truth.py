"""Per-principal, per-project evidence. Status reads never launch a backend."""
from __future__ import annotations
import asyncio
import json
import time
from collections import OrderedDict
from pathlib import Path
from .common import RuntimeFault, utc_now, exception_code


class CapabilityTruth:
    def __init__(self, backends, policy, ttl_seconds=120, clock=time.monotonic):
        self.backends, self.policy = backends, policy
        self.ttl = max(1, float(ttl_seconds))
        self.clock = clock
        self.evidence = OrderedDict()
        self.locks = {}
        self.preflights = {}

    @staticmethod
    def text(result):
        if hasattr(result, 'model_dump'):
            result = result.model_dump(mode='json', by_alias=True)
        if isinstance(result, dict):
            content = result.get('content', [])
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                return '\n'.join(c.get('text', '') for c in content if isinstance(c, dict))
            return json.dumps(result.get('structuredContent', result), ensure_ascii=False)
        return str(result)

    @staticmethod
    def classify(backend, tool, result):
        if hasattr(result,'model_dump'):result=result.model_dump(mode='json',by_alias=True)
        if isinstance(result,dict) and (result.get('isError') or result.get('is_error')):
            raise RuntimeFault('BACKEND_TOOL_ERROR','Backend reported an unsuccessful operation.')
        body = CapabilityTruth.text(result)
        lower = body.lower()
        if backend == 'codegraph' and any(s in lower for s in ["isn't indexed", 'no .codegraph/', 'not indexed']):
            raise RuntimeFault('PROJECT_NOT_INDEXED', 'CodeGraph has no usable index for this project.')
        state = 'READY'
        if backend == 'agent_memory' and tool == 'memory_sessions':
            try:
                data = json.loads(body)
                if isinstance(data, dict) and data.get('sessions') == []:
                    state = 'READY_EMPTY'
            except (ValueError, TypeError):
                pass
        if backend == 'serena' and tool == 'get_current_config' and 'language server status: ready' not in lower:
            state = 'DEGRADED'
        return state

    def record(self, owner, project, backend, state, tool, elapsed_ms, error=None):
        key = (owner, project, backend)
        self.evidence[key] = {'state': state, 'verified_at': utc_now(),
            'observed_monotonic': self.clock(), 'tool': tool,
            'latency_ms': round(elapsed_ms, 3), 'error_code': error}
        self.evidence.move_to_end(key)
        while len(self.evidence) > 2048:
            self.evidence.popitem(last=False)

    def failure(self, owner, project, backend, tool, started, exc):
        code = exception_code(exc)
        if type(exc).__name__=='ToolError':code='ToolError'
        if code=='ToolError':
            try: code=json.loads(str(exc)).get('error',code)
            except (ValueError,TypeError): pass
        state = 'UNAVAILABLE_FOR_PROJECT' if code == 'PROJECT_NOT_INDEXED' else 'DEGRADED'
        self.record(owner, project, backend, state, tool, (self.clock()-started)*1000, code)

    def _preflight(self, project, backend, spec):
        key = (project, backend)
        cached = self.preflights.get(key)
        now = self.clock()
        if cached and now - cached[0] < 10:
            return dict(cached[1])
        value = {'configured': bool(spec.get('enabled')), 'executable_present': False,
                 'index_present': None, 'reason': None}
        if value['configured']:
            try:
                value['executable_present'] = Path(spec['command']).is_file()
                if not value['executable_present']:
                    value['reason'] = 'EXECUTABLE_NOT_FOUND'
                if backend == 'codegraph':
                    # Do not inspect ancestors outside the authorized project.
                    value['index_present'] = (self.policy.roots[project]/'.codegraph').is_dir()
                    if not value['index_present']:
                        value['reason'] = 'PROJECT_NOT_INDEXED'
            except OSError:
                value['reason'] = 'ACCESS_DENIED'
        self.preflights[key] = (now, value)
        return dict(value)

    def snapshot(self, owner, projects):
        now = self.clock()
        rows = {}
        for project in projects:
            rows[project] = {}
            for backend, spec in self.backends.specs.items():
                pre = self._preflight(project, backend, spec)
                ev = self.evidence.get((owner, project, backend))
                age = max(0.0, now-ev['observed_monotonic']) if ev else None
                fresh = age is not None and age <= self.ttl
                actors = [a for key, a in self.backends.actors.items()
                          if key in {backend+':'+project, backend+':'+project+':'+owner}]
                live = any(a.task and not a.task.done() and a.ready and a.ready.done()
                    and not a.ready.cancelled() and a.ready.exception() is None for a in actors)
                state = 'NOT_CONFIGURED' if not pre['configured'] else (
                    'UNAVAILABLE_FOR_PROJECT' if pre['reason']=='PROJECT_NOT_INDEXED' else
                    'UNAVAILABLE' if pre['reason'] else ev['state'] if fresh else 'UNVERIFIED')
                rows[project][backend] = {**pre, 'state': state,
                    'connection_live': bool(live), 'operation_verified': bool(fresh and ev['state'] in {'READY','READY_EMPTY'}),
                    'evidence_stale': bool(ev and not fresh),
                    'last_verified_at': ev['verified_at'] if ev else None,
                    'last_probe_tool': ev['tool'] if ev else None,
                    'last_latency_ms': ev['latency_ms'] if ev else None,
                    'last_error_code': ev['error_code'] if ev else pre['reason'],
                    'evidence_age_seconds': round(age,3) if age is not None else None,
                    'declared_version': spec.get('observed_version')}
        return {'projects': rows, 'evidence_ttl_seconds': self.ttl,
                'probe_on_status': False, 'evidence_persistence': 'process_lifetime_only'}

    async def probe(self, owner, project, backend, caller):
        if backend not in self.backends.specs:
            raise RuntimeFault('BACKEND_NOT_CONFIGURED', 'Unknown backend.')
        key = (owner, project, backend)
        lock = self.locks.setdefault(key, asyncio.Lock())
        try:
            async with lock:
                ev = self.evidence.get(key)
                # Coalesce concurrent probes without freezing failures indefinitely.
                if ev and self.clock()-ev['observed_monotonic'] < 2:
                    return self.snapshot(owner, [project])['projects'][project][backend]
                pre = self._preflight(project, backend, self.backends.specs[backend])
                if not pre['configured'] or pre['reason']:
                    return self.snapshot(owner, [project])['projects'][project][backend]
                specs = {'desktop': ('list_directory', {'path':'','depth':1}),
                    'serena': ('get_current_config', {}),
                    'codegraph': ('codegraph_explore', {'query':'execution_start Broker','projectPath':str(self.policy.roots[project]),'maxFiles':1}),
                    'agent_memory': ('memory_sessions', {})}
                if backend not in specs:
                    raise RuntimeFault('PROBE_NOT_CONFIGURED', 'No approved read-only probe for this backend.')
                tool, args = specs[backend]
                started = self.clock()
                try:
                    result = await caller(backend, project, tool, args)
                    state = self.classify(backend, tool, result)
                    self.record(owner, project, backend, state, tool, (self.clock()-started)*1000)
                except Exception as exc:
                    self.failure(owner, project, backend, tool, started, exc)
                return self.snapshot(owner, [project])['projects'][project][backend]
        finally:
            # Entries are bounded by configured projects and backend names, not user input.
            if len(self.locks)>2048:
                self.locks = {k:v for k,v in self.locks.items() if v.locked()}
