"""Deterministic runtime documentation generated from the actual exported catalog."""
from __future__ import annotations
import hashlib
import math
import json
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from .common import atomic_json, atomic_bytes, canonical, digest, utc_now


class OperationMetrics:
    def __init__(self, sample_limit=256):
        self.lock = threading.Lock()
        self.sample_limit=sample_limit
        self.samples = defaultdict(lambda: deque(maxlen=sample_limit))
        self.counts = defaultdict(lambda: {'calls':0,'errors':0})

    def record(self, name, milliseconds, error=False):
        with self.lock:
            self.samples[name].append(float(milliseconds))
            self.counts[name]['calls'] += 1
            self.counts[name]['errors'] += int(bool(error))

    def snapshot(self):
        with self.lock:
            result = {}
            for name, values in self.samples.items():
                ordered = sorted(values)
                result[name] = {**self.counts[name], 'sample_count':len(ordered),
                    'p50_ms':round(ordered[(len(ordered)-1)//2],3),
                    'p95_ms':round(ordered[max(0,math.ceil(len(ordered)*.95)-1)],3),
                    'max_ms':round(ordered[-1],3)}
            return {'tools':result,'measurement':'server-side duration, not network round-trip',
                    'retained_samples_per_tool':self.sample_limit, 'percentile_method':'nearest_rank'}


class RuntimeDocumentation:
    def __init__(self, directory, source_dir, version, config):
        self.directory, self.source_dir = Path(directory), Path(source_dir)
        self.version = version
        # Allowlist only non-secret operational settings. Never serialize config wholesale.
        self.profile = {'stage':config.get('stage'),
            'broker':{k:config.get('broker',{}).get(k) for k in
                ['max_active','queue_limit','memory_gib','max_timeout_seconds']},
            'daemon_limit':config.get('daemon_manager',{}).get('max_active',2),
            'managed_daemon_count':len(config.get('managed_daemons',{})),
            'managed_windows_service_count':len(config.get('managed_windows_services',{})),
            'immutable_subpaths':{k:list(v) for k,v in sorted(config.get('immutable_subpaths',{}).items())},
            'desktop_commander_policy':'RETAINED_UNMODIFIED'}
        self.lock = threading.Lock()
        self.receipt = {'state':'NOT_GENERATED','runtime_version':version}
        self.expected = {}
        self.catalog = []

    def source_hashes(self):
        return {p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(self.source_dir.glob('*.py'))}

    def generate(self, catalog):
        self.catalog = sorted(catalog, key=lambda t:t['name'])
        source = self.source_hashes()
        tools = [{k:t[k] for k in ['name','description','inputSchema','annotations'] if k in t}
                 for t in self.catalog]
        semantic = {'runtime_version':self.version,'source_sha256':source,
                    'tools':tools,'profile':self.profile}
        binding = digest(semantic)
        manifest = {**semantic,'binding_sha256':binding}
        lines = ['# Smart Assistant MCP — runtime catalog', '',
                 'Runtime version: `'+self.version+'`',
                 'Source/catalog binding: `'+binding+'`', '',
                 'Generated from the running code and exported MCP schemas; not a design-only specification.', '',
                 'Desktop Commander is retained. No external service is managed implicitly.', '',
                 '## Operational contracts', '',
                 '- Status is cached; explicit capability probes execute bounded read-only checks.',
                 '- A live backend connection does not prove the presence or freshness of project data.',
                 '- execution_run uses the durable broker and the same idempotency key.',
                 '- Registered daemons use an independent queue and quota, but the shared memory governor.',
                 '- Unknown daemon outcomes are never automatically replayed.',
                 '- Native Windows controls require explicit service registration and existing OS rights.',
                 '- Immutable subpaths are rejected before writer-lock acquisition; releases are promoted by the governed release workflow.',
                 '- Detached process creation alone does not guarantee survival of a Windows service stop.',
                 '- Broker reattachment, service restart, Windows reboot and external outcome verification are distinct gates.', '',
                 '## Exported tools', '']
        for tool in tools:
            schema=tool.get('inputSchema',{})
            lines += ['### `'+tool['name']+'`', '', tool.get('description',''), '',
                      'Required arguments: '+(', '.join(schema.get('required',[])) or 'none')+'.', '']
        outputs = {'RUNTIME_MANIFEST.json':(canonical(manifest)+'\n').encode('utf-8'),
                   'CAPABILITIES.md':('\n'.join(lines)+'\n').encode('utf-8')}
        for name, content in outputs.items():
            path=self.directory/name
            if not path.is_file() or path.read_bytes()!=content:
                atomic_bytes(path, content)
        expected={name:hashlib.sha256(data).hexdigest() for name,data in outputs.items()}
        with self.lock:
            self.expected=expected
            self.source_expected=source
            self.receipt={'state':'SYNCHRONIZED','runtime_version':self.version,
                'tool_count':len(tools),'binding_sha256':binding,'generated_at':utc_now(),
                'directory':str(self.directory),'automatic_generation':True,
                'verification_scope':'runtime_source_and_exported_catalog',
                'global_wiki_freshness_verified':False}
        return self.status()

    def verify(self):
        with self.lock:
            expected=dict(self.expected)
            source=dict(getattr(self,'source_expected',{}))
        if not expected:
            return self.status()
        drift=[]
        for name, sha in expected.items():
            p=self.directory/name
            if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=sha:
                drift.append(name)
        if self.source_hashes()!=source:
            drift.append('runtime_source')
        with self.lock:
            self.receipt={**self.receipt,'state':'DRIFT' if drift else 'SYNCHRONIZED',
                          'drift':drift,'last_verified_at':utc_now()}
        return self.status()

    def status(self):
        with self.lock:
            return dict(self.receipt)