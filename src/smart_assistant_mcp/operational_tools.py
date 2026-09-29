"""Operational tools keep authorization in the existing MCP boundary."""
from __future__ import annotations

import asyncio
import json
import time

from mcp.server.mcpserver.exceptions import ToolError

from .common import RuntimeFault
from .store import TERMINAL


def register(mcp, config, require, mutation_tool, require_mutation_project, invoke,
             policy, broker, truth, backend_call, backend_tools, native, daemons, documentation, metrics):
    @mcp.tool()
    async def capability_probe(backend: str, project: str) -> dict:
        """Run one approved read-only backend probe. Coalesced by principal/project/backend."""
        owner=require('context:read',project)
        if backend=='desktop': require('workspace:read',project)
        try:
            async def probed_call(backend_name,project_name,tool_name,args):
                await backend_tools(backend_name,project_name)
                return await backend_call(backend_name,project_name,tool_name,args)
            return await truth.probe(owner,project,backend,probed_call)
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc

    @mcp.tool()
    async def project_info(project: str) -> dict:
        """Resolve one authorized project and its effective read/write capabilities."""
        owner=require('workspace:read',project)
        return {'project':project,'root':str(policy.roots[project]),
                'mutation_enabled':config.get('allow_mutations',False) and project in config.get('mutation_projects',[]),
                'capabilities':truth.snapshot(owner,[project])['projects'][project],
                'execution_boundary':'operating_system_account_not_filesystem_sandbox'}

    @mutation_tool()
    async def execution_run(project: str, argv: list[str], request_key: str,
                            timeout_seconds: int=300, wait_ms: int=5000,
                            output_length: int=4096) -> dict:
        """Submit once through the durable broker; briefly wait and return both output streams.

        When wait expires, execution continues and the SAME request_key resumes its receipt.
        This is not a second execution engine and never cancels a job on HTTP disconnect.
        """
        require_mutation_project(project)
        owner=require('process:execute',project)
        require('process:read',project)
        if type(wait_ms) is not int or not 0<=wait_ms<=8000 or type(output_length) is not int or not 4<=output_length<=16384:
            raise ToolError(json.dumps(RuntimeFault('INVALID_RANGE','wait_ms is 0..8000; output_length is 4..16384.').as_dict()))
        started=time.perf_counter(); failed=False
        try:
            admitted=await invoke(broker.submit,owner,project,argv,request_key,timeout_seconds,
                                 scope='process:execute',writes=True,project_scope=project,lane='L2')
            deadline=time.monotonic()+wait_ms/1000
            job=admitted
            while job['state'] not in TERMINAL and time.monotonic()<deadline:
                await asyncio.sleep(min(.05,max(0,deadline-time.monotonic())))
                job=await asyncio.to_thread(broker.store.get,admitted['id'],owner)
            stdout,stderr=await asyncio.gather(
                asyncio.to_thread(broker.read,admitted['id'],owner,'stdout',0,output_length),
                asyncio.to_thread(broker.read,admitted['id'],owner,'stderr',0,output_length))
            job=await asyncio.to_thread(broker.store.get,admitted['id'],owner)
            return {**broker.public(job),'new_admission':admitted['new_admission'],
                    'terminal':job['state'] in TERMINAL,'wait_expired':job['state'] not in TERMINAL,
                    'stdout':stdout,'stderr':stderr,'request_key':request_key,
                    'elapsed_ms':round((time.perf_counter()-started)*1000,3)}
        except RuntimeFault as exc:
            failed=True
            raise ToolError(json.dumps(exc.as_dict())) from exc
        finally:
            metrics.record('execution_run',(time.perf_counter()-started)*1000,failed)

    @mcp.tool()
    async def service_list(limit: int=100, prefix: str='') -> dict:
        """Read the cached native Windows service inventory. No PowerShell or process spawn."""
        return await invoke(native.service_list,limit,prefix,scope='process:read',gib=.02,lane='L0')

    @mcp.tool()
    async def service_status(name: str) -> dict:
        """Inspect one Windows service. Running does not establish application readiness."""
        return await invoke(native.service_status,name,scope='process:read',gib=.02,lane='L0')

    @mutation_tool()
    async def service_control(name: str, action: str, request_key: str) -> dict:
        """Start/stop/restart only an explicitly registered Windows service using existing OS rights.

        Configured control-plane and compatibility services are protected. No privilege elevation.
        """
        try: project=native.service_project(name)
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc
        owner=require('process:execute',project)
        require_mutation_project(project)
        return await invoke(native.service_control,owner,name,action,request_key,
                            writes=True,scope='process:execute',project_scope=project,gib=.02,lane='L2')

    @mcp.tool()
    async def process_inspect(pid: int, expected_create_time: float | None=None) -> dict:
        """Inspect a process without exposing command-line secrets; optionally verify PID identity."""
        return await invoke(native.process_inspect,pid,expected_create_time,scope='process:read',gib=.02,lane='L0')

    @mcp.tool()
    async def port_probe(port: int, host: str='127.0.0.1', timeout_ms: int=500) -> dict:
        """Bounded loopback-only TCP probe. Does not claim HTTP or application readiness."""
        return await invoke(native.port_probe,port,host,timeout_ms,scope='process:read',gib=.02,lane='L0')

    @mcp.tool()
    async def scheduled_task_status(task_path: str) -> dict:
        """Query one exact Windows Task Scheduler path via COM; actions and credentials are omitted."""
        return await invoke(native.scheduled_task_status,task_path,scope='process:read',gib=.02,lane='L0')

    @mcp.tool()
    async def daemon_status(name: str) -> dict:
        """Inspect a registered, owned daemon in the independent durable daemon queue."""
        try: project=daemons.project(name)
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc
        owner=require('process:read',project)
        return await invoke(daemons.status,owner,name,scope='process:read',project_scope=project,gib=.02,lane='L0')

    @mutation_tool()
    async def daemon_start(name: str, request_key: str) -> dict:
        """Idempotently admit one registered singleton daemon. Arbitrary caller argv is not accepted."""
        try: project=daemons.project(name)
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc
        owner=require('process:execute',project); require_mutation_project(project)
        return await invoke(daemons.start_service,owner,name,request_key,scope='process:execute',
                            project_scope=project,writes=True,gib=.02,lane='L2')

    @mutation_tool()
    async def daemon_stop(name: str, expected_execution_id: str) -> dict:
        """Request daemon stop only for the expected current instance; no PID reuse or generation race."""
        try: project=daemons.project(name)
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc
        owner=require('process:execute',project); require_mutation_project(project)
        return await invoke(daemons.stop_service,owner,name,expected_execution_id,scope='process:execute',
                            project_scope=project,writes=True,gib=.02,lane='L2')

    @mutation_tool()
    async def daemon_restart(name: str, request_key: str) -> dict:
        """Durable stop-then-start. Repeat the SAME key while WAITING_FOR_STOP; unknown outcomes block replay."""
        try: project=daemons.project(name)
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc
        owner=require('process:execute',project); require_mutation_project(project)
        return await invoke(daemons.restart_service,owner,name,request_key,scope='process:execute',
                            project_scope=project,writes=True,gib=.02,lane='L2')

    @mcp.tool()
    async def documentation_status(verify: bool=False) -> dict:
        """Read generated runtime documentation status; optionally verify source/catalog binding."""
        require('context:read')
        if verify:
            return await invoke(documentation.verify,scope='context:read',gib=.05,lane='L1')
        return documentation.status()

    @mcp.tool()
    async def operational_metrics() -> dict:
        """Read bounded latency/error samples. These are server timings, not end-to-end network benchmarks."""
        require('process:read')
        return metrics.snapshot()
