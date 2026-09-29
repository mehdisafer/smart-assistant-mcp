from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from contextlib import AsyncExitStack, asynccontextmanager

from .common import RuntimeFault


class BackendActor:
    """One owning async task per persistent MCP client; no cross-task context-manager exit."""
    def __init__(self,name,spec,cwd,governor):
        self.name,self.spec,self.cwd,self.governor=name,spec,cwd,governor
        self.queue=asyncio.Queue(maxsize=8)
        self.task=None
        self.ready=None
        self.catalog={}
        self.key='backend:'+name
        self.borrowers=0
        self.inflight=False
        self.active_future=None
        self.last_used=time.monotonic()
        self.completed_calls=0
        self.last_error=None

    async def start(self):
        if self.task and not self.task.done():
            await asyncio.shield(self.ready)
            return
        self.ready=asyncio.get_running_loop().create_future()
        self.task=asyncio.create_task(self._run(),name=self.key)
        await asyncio.shield(self.ready)

    async def _run(self):
        active_future=None
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
            from mcp_types import PaginatedRequestParams
            self.governor.acquire(self.key,float(self.spec.get('memory_gib',1)),1)
        except Exception as exc:
            self.ready.set_exception(exc)
            return
        try:
            env=dict(self.spec.get('env',{}))
            params=StdioServerParameters(command=self.spec['command'],args=self.spec.get('args',[]),
                                          env=env,cwd=str(self.cwd))
            async with AsyncExitStack() as stack:
                async with asyncio.timeout(self.spec.get('startup_timeout_seconds',30)):
                    streams=await stack.enter_async_context(stdio_client(params))
                    client=await stack.enter_async_context(ClientSession(*streams, read_timeout_seconds=self.spec.get('call_timeout_seconds',60)))
                    await client.initialize()
                self.catalog.clear()
                cursor=None
                seen_cursors=set()
                while True:
                    async with asyncio.timeout(30):
                        page=await client.list_tools(params=PaginatedRequestParams(cursor=cursor))
                    for tool in page.tools:
                        if tool.name in self.spec.get('allowed_tools',[]):
                            self.catalog[tool.name]=tool
                    cursor=page.next_cursor
                    if cursor is None: break
                    if cursor in seen_cursors or len(seen_cursors)>=16:
                        raise RuntimeFault('INVALID_CATALOG','Backend catalog pagination is cyclic or too large.')
                    seen_cursors.add(cursor)
                self.ready.set_result(True)
                while True:
                    item=await self.queue.get()
                    if item is None: break
                    tool,args,future,started=item
                    active_future=future
                    self.active_future=future
                    if future.cancelled():
                        self.active_future=None
                        continue
                    self.inflight=True
                    started.set()
                    try:
                        async with asyncio.timeout(self.spec.get('call_timeout_seconds',40)):
                            result=await client.call_tool(tool,args)
                        size=len(result.model_dump_json())
                        if size>512*1024:
                            raise RuntimeFault('OUTPUT_LIMIT','Backend result exceeds 512 KiB; narrow the query.')
                        body='\n'.join(getattr(c,'text','') for c in result.content)
                        if self.name.startswith('codegraph:') and ('busy serving other concurrent requests' in body.lower() or 'waited 45s in the queue' in body.lower()):
                            raise RuntimeFault('BACKEND_BUSY','CodeGraph returned no answer because its queue is busy.',True)
                        if result.is_error:
                            raise RuntimeFault('BACKEND_TOOL_ERROR','Backend returned an error result.')
                        self.completed_calls+=1
                        self.last_error=None
                        if not future.done(): future.set_result(result)
                    except asyncio.TimeoutError:
                        if not future.done():
                            future.set_exception(RuntimeFault('BACKEND_RESULT_UNKNOWN',
                                'Backend timed out. A mutation may have occurred; do not replay automatically.'))
                        break
                    except Exception as exc:
                        self.last_error=getattr(exc,'code',type(exc).__name__)
                        if not future.done(): future.set_exception(exc)
                    finally:
                        self.inflight=False
                        self.active_future=None
                        self.last_used=time.monotonic()
        except BaseException as exc:
            if not self.ready.done(): self.ready.set_exception(exc)
        finally:
            if active_future is not None and not active_future.done():
                active_future.set_exception(RuntimeFault('BACKEND_RESULT_UNKNOWN','Backend closed during a call; do not replay a mutation automatically.'))
            self.governor.release(self.key)
            while not self.queue.empty():
                item=self.queue.get_nowait()
                if item is not None and not item[2].done():
                    item[2].set_exception(RuntimeFault('BACKEND_UNAVAILABLE','Backend connection closed.',True))

    async def call(self,name,args,total_timeout_seconds=None):
        await self.start()
        if name not in self.catalog:
            raise RuntimeFault('TOOL_DENIED','This backend tool is not approved.')
        import jsonschema
        jsonschema.Draft202012Validator(self.catalog[name].input_schema).validate(args)
        future=asyncio.get_running_loop().create_future()
        started=asyncio.Event()
        try:
            self.queue.put_nowait((name,args,future,started))
        except asyncio.QueueFull:
            raise RuntimeFault('BACKEND_QUEUE_FULL','Backend queue is full.',True)
        call_timeout=float(self.spec.get('call_timeout_seconds',40))
        queue_timeout=float(self.spec.get('queue_timeout_seconds',max(2.0,min(15.0,call_timeout*.25))))
        total=float(total_timeout_seconds) if total_timeout_seconds is not None else queue_timeout+call_timeout+2.0
        total=max(0.05,min(total,300.0))
        began=time.monotonic()
        try:
            async with asyncio.timeout(min(queue_timeout,total)):
                await started.wait()
        except asyncio.TimeoutError as exc:
            if not future.done():
                future.cancel()
            raise RuntimeFault('BACKEND_QUEUE_TIMEOUT',
                'Backend call did not start within the bounded queue budget; retry later.',True) from exc
        remaining=max(0.05,total-(time.monotonic()-began))
        try:
            async with asyncio.timeout(remaining):
                return await future
        except asyncio.TimeoutError as exc:
            if not future.done():
                future.cancel()
            raise RuntimeFault('BACKEND_RESULT_UNKNOWN',
                'Backend exceeded the result budget after execution started; inspect mutation outcome before retry.') from exc

    async def close(self):
        if self.task and not self.task.done():
            try: self.queue.put_nowait(None)
            except asyncio.QueueFull: self.task.cancel()
            done,_=await asyncio.wait([self.task],timeout=10)
            if not done:
                self.task.cancel()
                done,_=await asyncio.wait([self.task],timeout=10)
            if not done: raise RuntimeFault('BACKEND_SHUTDOWN_TIMEOUT','Worker did not exit; slot remains reserved.')


class BackendManager:
    """Bounded warm pool: borrowed or executing actors are never evicted."""
    def __init__(self,specs,policy,governor,max_hot=3,actor_factory=BackendActor):
        if type(max_hot) is not int or max_hot < 1: raise ValueError('max_hot must be positive')
        self.specs,self.policy,self.governor,self.max_hot=specs,policy,governor,max_hot
        self.actor_factory=actor_factory
        self.actors={}
        self.lock=asyncio.Lock()
        self.closing=False

    @asynccontextmanager
    async def use(self,name,project,partition=None):
        spec=self.specs.get(name)
        if not spec or not spec.get('enabled',False):
            raise RuntimeFault('BACKEND_DISABLED','Backend has not passed its connection qualification.')
        cwd=self.policy.resolve(project,'',True)
        key=name+':'+project+(':'+partition if partition else '')
        if partition is not None:
            spec={**spec,'env':{**spec.get('env',{}),'SA_COMPAT_PARTITION':partition}}
        async with self.lock:
            if self.closing: raise RuntimeFault('BACKEND_UNAVAILABLE','Backend pool is stopping.',True)
            if key not in self.actors:
                if len(self.actors)>=self.max_hot:
                    idle=[(k,a) for k,a in self.actors.items()
                          if a.borrowers==0 and not a.inflight and a.queue.empty()]
                    if not idle:
                        raise RuntimeFault('HOT_POOL_FULL','All backend slots are active; retry later.',True)
                    victim_key,victim=min(idle,key=lambda pair:pair[1].last_used)
                    # Only close an idle actor; its owning task reaps the stdio context.
                    await victim.close()
                    self.actors.pop(victim_key,None)
                self.actors[key]=self.actor_factory(key,spec,cwd,self.governor)
            actor=self.actors[key]
            actor.borrowers+=1
        try:
            await actor.start()
            yield actor
        finally:
            async with self.lock:
                actor.borrowers-=1
                actor.last_used=time.monotonic()
                if actor.borrowers==0 and actor.task and actor.task.done():
                    if self.actors.get(key) is actor:
                        self.actors.pop(key,None)

    async def reap_idle(self,max_age_seconds=300):
        """Close only this pool's unborrowed idle clients; never unrelated processes."""
        now=time.monotonic()
        closed=[]
        async with self.lock:
            for key,actor in list(self.actors.items()):
                if actor.borrowers==0 and not actor.inflight and actor.queue.empty() and now-actor.last_used>=max_age_seconds:
                    await actor.close()
                    if self.actors.get(key) is actor: self.actors.pop(key,None)
                    closed.append(key)
        return closed

    async def close(self):
        async with self.lock:
            self.closing=True
            await asyncio.gather(*(actor.close() for actor in self.actors.values()),return_exceptions=True)
            self.actors.clear()

    def status(self):
        return {name:{'enabled':spec.get('enabled',False),
                      'command_exists':Path(spec['command']).is_file(),
                      'allowed_tools':spec.get('allowed_tools',[]),
                      'declared_version':spec.get('observed_version'),
                      'live_connection_verified':any(key.startswith(name+':') and actor.task and
                            not actor.task.done() and actor.ready and actor.ready.done() and
                            not actor.ready.cancelled() and actor.ready.exception() is None
                            for key,actor in self.actors.items())}
                for name,spec in self.specs.items()}