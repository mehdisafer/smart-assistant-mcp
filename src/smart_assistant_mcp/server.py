from __future__ import annotations

import asyncio
import contextvars
import json
import os
import uuid
import time
from contextlib import asynccontextmanager
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings

from . import __version__
from .auth import IdentityRegistry
from .backends import BackendManager
from .broker import Broker
from .common import RuntimeFault
from .filesystem import FileSystem, PathPolicy
from .governor import Governor
from .policy import ProjectAccess
from .store import StateStore, TERMINAL
from .health_cache import HealthCache
from .capability_truth import CapabilityTruth
from .windows_native import WindowsNative
from .daemons import DaemonManager
from .runtime_docs import RuntimeDocumentation, OperationMetrics
from .wiki import WikiIndex
from .searches import SearchManager
from .processes import ProcessManager
from .desktop_compat import DesktopCompatibility, WRITE_TOOLS as COMPAT_WRITES


from .http_limits import RequestBounds


def build(config: dict):
    root=Path(config['root'])
    host=config.get('host','127.0.0.1')
    if host!='127.0.0.1' or config.get('public_exposure',False):
        raise RuntimeError('This candidate is loopback-only. Public/OAuth qualification is a separate gate.')
    port=int(config.get('port',8765))
    state_dir=Path(config.get('state_dir',str(root/'data'/'state-v2')))
    store=StateStore(state_dir/'runtime.sqlite3')
    health_cache=HealthCache(store)
    policy=PathPolicy(config['projects'],config.get('immutable_subpaths',{}))
    grants=ProjectAccess(config.get('principals',{}))
    filesystem=FileSystem(policy,state_dir)
    governor=Governor(str(root),config.get('governor'))
    wiki=WikiIndex(Path(config['wiki']['root']),state_dir/'wiki.sqlite3',Path(config['wiki']['manifest']))
    searches=SearchManager(policy,state_dir/'search-sessions',governor)
    processes=ProcessManager()
    broker=Broker(store,governor,policy,root/'data'/'executions-v2',config.get('broker'))
    backends=BackendManager(config.get('backends',{}),policy,governor,max_hot=int(config.get('max_hot_backends',3)))
    desktop=DesktopCompatibility(policy,filesystem,backends,config['compatibility_state_dir']) if config.get('backends',{}).get('desktop',{}).get('enabled',False) else None
    identities=IdentityRegistry(root/'config'/'identities.json')
    truth=CapabilityTruth(backends,policy,config.get('capability_ttl_seconds',120))
    metrics=OperationMetrics()
    documentation=RuntimeDocumentation(state_dir/'runtime-docs',Path(__file__).parent,__version__,config)
    native=WindowsNative(store,config.get('managed_windows_services',{}),config.get('protected_windows_services',[]))
    daemon_cfg={**broker.config,**config.get('daemon_manager',{}),'kind':'daemon','priority':1}
    daemon_cfg['max_active']=int(config.get('daemon_manager',{}).get('max_active',2))
    daemon_cfg['memory_gib']=float(config.get('daemon_manager',{}).get('memory_gib',.25))
    daemon_store=StateStore(state_dir/'daemons'/'runtime.sqlite3')
    daemon_broker=Broker(daemon_store,governor,policy,root/'data'/'daemon-runtime'/'executions',daemon_cfg)
    daemons=DaemonManager(daemon_broker,config.get('managed_daemons',{}))

    async def retire_idle_backends():
        while True:
            await asyncio.sleep(5)
            pressure=governor.status()['pressure']
            age=0 if pressure in {'HIGH','CRITICAL','EMERGENCY'} else 300 if pressure == 'PRESSURE' else 1800
            await backends.reap_idle(age)

    @asynccontextmanager
    async def lifespan(_):
        governor.start()
        health_cache.start()
        processes.start()
        native.start()
        catalog=await mcp.list_tools()
        await asyncio.to_thread(documentation.generate,[t.model_dump(mode='json',by_alias=True) for t in catalog])
        broker_enabled=bool(broker.config.get('enabled',False))
        if broker_enabled:
            broker.start()
            daemon_broker.start()
        maintenance=asyncio.create_task(retire_idle_backends(),name='mcp-idle-backend-reaper')
        try: yield {}
        finally:
            maintenance.cancel()
            await asyncio.gather(maintenance,return_exceptions=True)
            await backends.close()
            if broker_enabled:
                broker.stop()
            daemon_broker.stop()
            processes.stop()
            native.stop()
            health_cache.stop()
            governor.stop()

    identity_context=contextvars.ContextVar('smart_assistant_mcp_identity',default=None)

    mcp=MCPServer('Smart Assistant MCP',version=__version__,lifespan=lifespan,
                  instructions='Use Wiki for documentation, backend_tools for approved code tools, and durable executions for commands. '
                               'A queued execution is not completed. Never repeat a mutation after an ambiguous result.')

    class StaticBearerAuth:
        """Private loopback bearer auth without advertising OAuth/PRMD metadata.

        A separately authenticated ingress may inject the static bearer locally.
        This loopback server does not advertise or implement browser OAuth metadata.
        """
        def __init__(self,app):
            self.app=app

        @staticmethod
        async def response(send,status,body):
            payload=json.dumps(body,separators=(',',':')).encode('utf-8')
            await send({'type':'http.response.start','status':status,'headers':[
                (b'content-type',b'application/json'),
                (b'content-length',str(len(payload)).encode('ascii')),
                (b'cache-control',b'no-store'),
            ]})
            await send({'type':'http.response.body','body':payload})

        async def __call__(self,scope,receive,send):
            if scope.get('type')!='http':
                return await self.app(scope,receive,send)
            path=scope.get('path','')
            if path.startswith('/.well-known/'):
                return await self.response(send,404,{'error':'not_found'})
            values=[v.decode('latin1') for k,v in scope.get('headers',[]) if k.lower()==b'authorization']
            if len(values)!=1:
                return await self.response(send,401,{'error':'unauthorized'})
            authorization=values[0]
            if not authorization.lower().startswith('bearer '):
                return await self.response(send,401,{'error':'unauthorized'})
            token=authorization[7:].strip()
            record=identities.verify(token)
            if record is None:
                return await self.response(send,401,{'error':'unauthorized'})
            if 'mcp:use' not in record['scopes']:
                return await self.response(send,403,{'error':'insufficient_scope'})
            marker=identity_context.set(record)
            try:
                return await self.app(scope,receive,send)
            finally:
                identity_context.reset(marker)

    def mutation_tool():
        return mcp.tool() if config.get('allow_mutations',False) else (lambda fn:fn)

    mutation_projects=set(config.get('mutation_projects',[]))
    unknown_mutation_projects=mutation_projects-set(policy.roots)
    if unknown_mutation_projects:
        raise RuntimeError('Unknown mutation projects: '+','.join(sorted(unknown_mutation_projects)))

    def require_mutation_project(project):
        if project not in mutation_projects:
            raise ToolError('MUTATION_PROJECT_DENIED: project is read-only for this service.')

    def require(scope,project=None):
        identity=identity_context.get()
        if identity is None or scope not in identity['scopes']:
            raise ToolError('FORBIDDEN: required scope '+scope)
        owner=identity['owner']
        if project is not None:
            try: grants.require(owner,project)
            except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc
        return owner

    async def invoke(function,*args,writes=False,scope='context:read',gib=.02,priority=1,project_scope=None,lane=None):
        require(scope,project_scope)
        try:
            key='call:'+uuid.uuid4().hex
            governor.acquire(key,gib,priority,writes,lane)
            task=asyncio.create_task(asyncio.to_thread(function,*args))
            started=time.perf_counter()
            def completed(finished):
                governor.release(key)
                metrics.record(getattr(function,'__qualname__',function.__name__),(time.perf_counter()-started)*1000,finished.cancelled() or finished.exception() is not None)
            task.add_done_callback(completed)
            # Cancellation of the HTTP request must not prematurely release a running thread's resources.
            return await asyncio.shield(task)
        except RuntimeFault as exc:
            raise ToolError(json.dumps(exc.as_dict())) from exc

    @mcp.tool()
    async def runtime_health() -> dict:
        """Inspect cached telemetry; this call does not spawn a GPU probe or index files."""
        owner=require('mcp:use')
        counters=health_cache.snapshot(owner) if 'process:read' in identity_context.get()['scopes'] else None
        executions=counters['counts'] if counters else None
        return {'version':__version__,'release_stage':config.get('stage','LOCAL_QUALIFICATION'),
                'resources':governor.status(),'executions':executions,'execution_counters':counters,'execution_scope':'current_identity','mutations_enabled':bool(config.get('allow_mutations',False)),
                'broker_error':broker.last_error,'public_exposure':False,
                'documentation':documentation.status(),'daemon_broker_error':daemon_broker.last_error}

    @mcp.tool()
    async def capabilities_status(project: str | None=None) -> dict:
        """Distinguish configured backends from verified live connections."""
        require('mcp:use')
        owner=identity_context.get()['owner']
        projects=config.get('principals',{}).get(owner,{}).get('projects',[])
        if project is not None:
            require('context:read',project)
            projects=[project]
        return {'backends':backends.status(),'capability_truth':truth.snapshot(owner,projects),
                'documentation':documentation.status(),'native_execution_enabled':broker.config['enabled'],
                'wiki':await asyncio.to_thread(wiki.status),
                'effective_access':{'identity':owner,'projects':projects,
                  'mutation_projects':sorted(set(projects)&mutation_projects),'os_boundary':'service_account_not_project_sandbox'},
                'execution_limits':{k:broker.config[k] for k in ('max_active','queue_limit','memory_gib','max_timeout_seconds','max_output_bytes')}}

    @mcp.tool()
    async def wiki_search(query: str,limit: int=10) -> dict:
        """Search the derived Wiki index with source hashes and freshness indicators."""
        return await invoke(wiki.search,query,limit,gib=.05,lane='L1')

    @mcp.tool()
    async def wiki_read(relative_path: str,offset: int=0,length: int=200) -> dict:
        """Read bounded lines from the existing canonical Wiki, without changing it."""
        return await invoke(wiki.read,relative_path,offset,length,gib=.05,lane='L1')

    @mcp.tool()
    async def wiki_refresh(relative_paths: list[str]) -> dict:
        """Refresh at most 128 explicit Wiki pages per batch. Use remaining for continuation; never scan the whole disk."""
        return await invoke(wiki.refresh_paths,relative_paths,writes=True,scope='maintenance:run',gib=.25,priority=3,lane='L4')

    @mcp.tool()
    async def filesystem_read(project: str,relative_path: str,offset: int=0,length: int=200) -> dict:
        """Read a registered workspace text file and return its hash for optimistic writes."""
        return await invoke(filesystem.read,project,relative_path,offset,length,scope='workspace:read',project_scope=project,gib=.02,lane='L0')

    @mcp.tool()
    async def filesystem_list(project: str,relative_path: str='',limit: int=100) -> dict:
        """List a bounded number of entries from a registered project."""
        return await invoke(filesystem.list,project,relative_path,limit,scope='workspace:read',project_scope=project,gib=.02,lane='L0')

    @mcp.tool()
    async def filesystem_search(project: str,query: str,limit: int=20) -> dict:
        """Bounded literal text search. The partial flag must not be mistaken for an exhaustive result."""
        return await invoke(filesystem.search,project,query,limit,scope='workspace:read',project_scope=project,gib=.08,lane='L1')

    @mcp.tool()
    async def search_start(project: str,relative_path: str,pattern: str,search_type: str='content',
                           file_pattern: str | None=None,ignore_case: bool=True,max_results: int=200,
                           include_hidden: bool=False,context_lines: int=2,timeout_seconds: float=30,
                           literal: bool=False) -> dict:
        """Start a durable bounded search. L1 fast-path stays available under memory pressure."""
        owner=require('workspace:read',project)
        try:
            return await asyncio.to_thread(searches.start,owner,project,relative_path,pattern,search_type,
                                           file_pattern,ignore_case,max_results,include_hidden,
                                           context_lines,timeout_seconds,literal)
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc

    @mcp.tool()
    async def search_results(session_id: str,offset: int=0,length: int=100) -> dict:
        """Read persisted results of one owned search session."""
        owner=require('workspace:read')
        return await invoke(searches.results,owner,session_id,offset,length,
                            scope='workspace:read',gib=.02,lane='L0')

    @mcp.tool()
    async def search_list(limit: int=50) -> dict:
        """List this identity's durable search sessions."""
        owner=require('workspace:read')
        return await invoke(searches.list,owner,limit,scope='workspace:read',gib=.02,lane='L0')

    @mcp.tool()
    async def search_stop(session_id: str) -> dict:
        """Request cancellation of one owned search without deleting its persisted results."""
        owner=require('workspace:read')
        return await invoke(searches.stop,owner,session_id,scope='workspace:read',gib=.02,lane='L0')

    @mcp.tool()
    async def process_list(limit: int=100,sort_by: str='name') -> dict:
        """Fast native Windows process discovery. Use process_inspect for fresh CPU/memory details."""
        return await invoke(processes.list,limit,sort_by,scope='process:read',gib=.02,lane='L0')

    @mutation_tool()
    async def process_terminate(pid: int,expected_create_time: float,force: bool=False) -> dict:
        """Terminate a non-critical process using PID+creation-time protection against PID reuse."""
        if not config.get('process_admin_enabled',False):
            raise ToolError('PROCESS_ADMIN_DISABLED: operator has not enabled process termination.')
        return await invoke(processes.terminate,pid,expected_create_time,force,
                            scope='process:execute',writes=True,gib=.02,lane='L2')

    @mutation_tool()
    async def filesystem_write(project: str,relative_path: str,content: str,expected_sha256: str) -> dict:
        """Atomic text replacement with a retained backup. Use CREATE only for a nonexistent path."""
        require_mutation_project(project)
        return await invoke(filesystem.write,project,relative_path,content,expected_sha256,
                            scope='workspace:write',writes=True,project_scope=project,gib=.05,lane='L2')

    @mutation_tool()
    async def execution_start(project: str,argv: list[str],request_key: str,timeout_seconds: int=300) -> dict:
        """Durably admit a command. Full executable path required; repeats use the same idempotency key.

        Commands run with the OS account's rights, not in a project filesystem sandbox.
        """
        require_mutation_project(project)
        owner=require('process:execute',project)
        return await invoke(broker.submit,owner,project,argv,request_key,timeout_seconds,
                            scope='process:execute',writes=True)

    @mcp.tool()
    async def execution_read(execution_id: str,stream: str='stdout',cursor: int=0,length: int=16384) -> dict:
        """Read persisted output using a caller-owned byte cursor, even after an HTTP reconnect."""
        owner=require('process:read')
        try: return await asyncio.to_thread(broker.read,execution_id,owner,stream,cursor,length)
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc

    @mcp.tool()
    def execution_list(limit: int=30) -> dict:
        """List this identity's executions, including queued and ambiguous states."""
        owner=require('process:read')
        return {'executions':[broker.public(x) for x in store.recent_jobs(owner,limit)]}

    @mutation_tool()
    def execution_cancel(execution_id: str) -> dict:
        """Request cancellation of an owned execution; this is not an instantaneous kill acknowledgement."""
        owner=require('process:execute')
        result=broker.public(store.cancel(execution_id,owner))
        broker.wake()
        return result

    @mutation_tool()
    def execution_input(execution_id: str,text: str,request_key: str) -> dict:
        """Send terminal input, including required newlines, using an idempotency key."""
        owner=require('process:execute')
        return store.input(execution_id,owner,text,request_key)

    @mcp.tool()
    async def backend_tools(backend: str,project: str) -> dict:
        """List only approved tools of a qualified Serena, CodeGraph or Agent Memory backend."""
        owner=require('context:read',project)
        if backend=='desktop':
            require('workspace:read',project)
            if desktop is None: raise ToolError('BACKEND_DISABLED: Desktop compatibility not enabled.')
            try: return await desktop.tools(project,owner)
            except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc
        try:
            async with backends.use(backend,project) as actor:
                return {'tools':[t.model_dump(mode='json',by_alias=True) for t in actor.catalog.values()]}
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc

    @mcp.tool()
    async def backend_call(backend: str,project: str,tool: str,arguments: dict) -> dict:
        """Call one explicitly approved backend tool after consulting backend_tools for its exact schema."""
        owner=require('context:read',project)
        if backend=='desktop':
            if desktop is None: raise ToolError('BACKEND_DISABLED: Desktop compatibility not enabled.')
            writes=tool in COMPAT_WRITES
            require('workspace:write' if writes else 'workspace:read',project)
            if writes: require_mutation_project(project)
            try:
                key='compat-call:'+uuid.uuid4().hex
                lane='L4' if tool=='write_pdf' else ('L2' if writes else 'L1')
                estimate=.75 if tool=='write_pdf' else .03
                priority=3 if tool=='write_pdf' else 1
                governor.acquire(key,estimate,priority,writes,lane)
                task=asyncio.create_task(desktop.call(tool,arguments,project,owner))
                task.add_done_callback(lambda finished: governor.release(key))
                started=time.monotonic()
                try:
                    result=await asyncio.shield(task)
                    state=truth.classify(backend,tool,result)
                    truth.record(owner,project,backend,state,tool,(time.monotonic()-started)*1000)
                    return result
                except Exception as exc:
                    truth.failure(owner,project,backend,tool,started,exc)
                    raise
            except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc
        arguments=dict(arguments)
        if backend == 'serena' and 'relative_path' in arguments:
            policy.resolve(project,arguments['relative_path'],True)
        if backend == 'codegraph':
            # CodeGraph accepts an absolute projectPath. Never trust the caller's path:
            # bind it to the already-authorized project root to prevent scope bypass.
            arguments['projectPath']=str(policy.roots[project])
        try:
            async with backends.use(backend,project) as actor:
                # Allowlists must contain only read-oriented tools until mutation gates pass.
                started=time.monotonic()
                try:
                    result=await actor.call(tool,arguments)
                    state=truth.classify(backend,tool,result)
                    truth.record(owner,project,backend,state,tool,(time.monotonic()-started)*1000)
                    return result.model_dump(mode='json',by_alias=True)
                except Exception as exc:
                    truth.failure(owner,project,backend,tool,started,exc)
                    raise
        except RuntimeFault as exc: raise ToolError(json.dumps(exc.as_dict())) from exc

    from .operational_tools import register
    register(mcp,config,require,mutation_tool,require_mutation_project,invoke,policy,broker,truth,backend_call,backend_tools,native,daemons,documentation,metrics)

    app=mcp.streamable_http_app(stateless_http=True,json_response=True,
            transport_security=TransportSecuritySettings(
                allowed_hosts=[f'127.0.0.1:{port}',f'localhost:{port}'],allowed_origins=[]))
    app=StaticBearerAuth(app)
    return RequestBounds(app),mcp


def main():
    import uvicorn
    config_path=Path(os.environ.get('SA_MCP_CONFIG','config/runtime.json')).expanduser().resolve()
    config=json.loads(config_path.read_text(encoding='utf-8-sig'))
    app,_=build(config)
    uvicorn.run(app,host='127.0.0.1',port=config.get('port',8765),access_log=False,
                proxy_headers=False,limit_concurrency=64,timeout_keep_alive=10)


if __name__=='__main__': main()