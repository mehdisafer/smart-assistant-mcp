"""Governed file-format compatibility. Never starts the paid Remote client.
Terminal sessions stay in the native durable execution broker.
"""
from __future__ import annotations
import asyncio, copy, hashlib, json, re, shutil, sqlite3, time
from contextlib import ExitStack, contextmanager
from pathlib import Path
from .common import RuntimeFault, atomic_bytes
from .filesystem import FileLock

READ_TOOLS={'read_file','read_multiple_files','list_directory','get_file_info'}
WRITE_TOOLS={'write_file','edit_block','create_directory','move_file','write_pdf'}
# Stateful searches and PDF rendering are intentionally not admitted until their
# ownership/lifecycle and asset/network policies have been qualified.
TOOLS=READ_TOOLS|WRITE_TOOLS
DESCRIPTIONS={
 'read_file':'Read a local file in the authorized project. Relative path only. Text offsets support positive ranges and negative tails. XLSX: sheet and range A1:B2. DOCX: outline by default, XML when offset>0. URL fetch is not enabled.',
 'read_multiple_files':'Read at most 16 explicit relative file paths. Missing individual files are reported without discarding successful reads.',
 'get_file_info':'Inspect a relative file or directory. Regular files up to 32 MiB include smart_assistant.sha256 in the visible text receipt; use that hash for a subsequent mutation.',
 'list_directory':'List relative directory contents with bounded depth 1..4. The output may truncate nested directories; do not assume it is exhaustive.',
 'write_file':'Create, replace or append a local text file, JSON-shaped XLSX or new DOCX. Relative path only. Required _request_key deduplicates retries. Required _expected_sha256 is CREATE for a new target, otherwise its current get_file_info hash. Existing bytes are backed up.',
 'edit_block':'Edit a relative text/DOCX file using exact old_string/new_string, or XLSX cells using range Sheet!A1:B2 and content as a 2D array. Required _expected_sha256 must match get_file_info. Required stable _request_key deduplicates retries. A backup is retained.',
 'create_directory':'Create a relative directory under the authorized project. Supply a stable _request_key; repeated identical requests are deduplicated.',
 'move_file':'Move or rename a file or directory within one authorized project. Relative source and destination only. Destination must not exist. _expected_sha256 must match the source token from get_file_info; _request_key must remain stable across retries.',
 'write_pdf':'Create a PDF from bounded Markdown content in the authorized project. Relative .pdf path only. Existing targets require their current SHA-256; CREATE is required for a new target. This heavy operation runs only in L4/NORMAL resource conditions.'}

def visible_receipt(result):
    receipt=result.get('smart_assistant')
    if receipt is not None:
        content=result.setdefault('content',[])
        content[:]=[item for item in content if not (item.get('type')=='text' and item.get('text','').startswith('SMART_ASSISTANT_RECEIPT '))]
        content.append({'type':'text','text':'SMART_ASSISTANT_RECEIPT '+json.dumps(receipt,ensure_ascii=True,sort_keys=True)})
    return result

PATH_KEYS={'read_file':['path'],'get_file_info':['path'],'list_directory':['path'],
 'write_file':['path'],'edit_block':['file_path'],'create_directory':['path'],
 'move_file':['source','destination'],'write_pdf':['path']}
class DesktopCompatibility:
    def __init__(self,policy,filesystem,manager,state_dir):
        self.policy,self.filesystem,self.manager=policy,filesystem,manager
        spec=getattr(manager,'specs',{}).get('desktop',{}) if isinstance(getattr(manager,'specs',{}),dict) else {}
        call_timeout=float(spec.get('call_timeout_seconds',45))
        queue_timeout=float(spec.get('queue_timeout_seconds',max(2.0,min(15.0,call_timeout*.25))))
        self.backend_call_budget_seconds=max(1.0,min(180.0,call_timeout+queue_timeout+2.0))
        self.root=Path(state_dir); self.root.mkdir(parents=True,exist_ok=True)
        self.db=self.root/'operations.sqlite3'
        self.chrome_profiles=self.root/'chrome-profiles'
        self.chrome_profiles.mkdir(parents=True,exist_ok=True)
        cutoff=time.time()-86400
        for item in self.chrome_profiles.glob('*'):
            try:
                if item.is_dir() and item.stat().st_mtime < cutoff:
                    shutil.rmtree(item,ignore_errors=True)
            except OSError:
                pass
        with self.connection() as c:
            c.execute('PRAGMA journal_mode=WAL')
            c.execute('CREATE TABLE IF NOT EXISTS operations(owner TEXT,project TEXT,request_key TEXT,signature TEXT,state TEXT,result TEXT,at REAL,PRIMARY KEY(owner,project,request_key))')
    @contextmanager
    def connection(self):
        c=sqlite3.connect(self.db,timeout=2); c.row_factory=sqlite3.Row
        try:
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()
    async def tools(self,project,owner):
        async with self.manager.use('desktop',project,partition=owner) as actor:
            result=[]
            for name,t in actor.catalog.items():
                if name not in TOOLS:continue
                item=t.model_dump(mode='json',by_alias=True); schema=copy.deepcopy(item['inputSchema'])
                props=schema.setdefault('properties',{})
                if name in WRITE_TOOLS:
                    props['_request_key']={'type':'string','minLength':8,'maxLength':128,'description':'Stable idempotency key. Keep it unchanged after network uncertainty.'}
                    schema.setdefault('required',[]).append('_request_key')
                    if name in {'write_file','edit_block','move_file','write_pdf'}:
                        props['_expected_sha256']={'type':'string','description':'Version token from get_file_info; CREATE only for a new write_file target.'}
                        schema['required'].append('_expected_sha256')
                item['inputSchema']=schema
                item['description']=DESCRIPTIONS[name]
                props.pop('origin',None)
                if 'isUrl' in props: props['isUrl']={'type':'boolean','const':False,'default':False}
                if name=='write_pdf':
                    props.pop('outputPath',None)
                    props['content']={'type':'string','minLength':1,'maxLength':500000}
                item['annotations']={'readOnlyHint':name in READ_TOOLS,'destructiveHint':name in WRITE_TOOLS and name!='create_directory','idempotentHint':True,'openWorldHint':False}
                # Upstream embedded UI assets are not registered on our MCP.
                item.pop('_meta',None); result.append(item)
            return {'tools':result,'engine':'desktop-commander-oss@0.2.51','remote_service_dependency':False,'terminal':'Use native execution_* tools for durable jobs.'}
    def normalize(self,name,args,project):
        if name not in TOOLS:raise RuntimeFault('TOOL_DENIED','Compatibility tool is not qualified.')
        args=copy.deepcopy(args)
        key=args.pop('_request_key',None); expected=args.pop('_expected_sha256',None)
        if args.get('isUrl'):raise RuntimeFault('URL_NOT_QUALIFIED','URL fetching is outside this local-file adapter.')
        paths=[]
        for k in PATH_KEYS.get(name,[]):
            if k not in args:raise RuntimeFault('INVALID_ARGUMENTS','Missing path: '+k)
            must_exist=name in READ_TOOLS or name=='edit_block' or (name=='move_file' and k=='source')
            value=(self.policy.resolve_mutation(project,args[k],must_exist)
                   if name in WRITE_TOOLS else self.policy.resolve(project,args[k],must_exist))
            args[k]=str(value); paths.append(value)
        if name=='read_multiple_files':
            supplied=args.get('paths',[])
            if not isinstance(supplied,list) or not 1<=len(supplied)<=16:raise RuntimeFault('INVALID_ARGUMENTS','At most 16 explicit files.')
            paths=[self.policy.resolve(project,p,False) for p in supplied];args['paths']=[str(p) for p in paths]
        if name in WRITE_TOOLS and (not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{8,128}',key)):
            raise RuntimeFault('REQUEST_KEY_REQUIRED','A stable _request_key is required for mutations.')
        if name in {'write_file','edit_block','move_file','write_pdf'} and (not isinstance(expected,str) or (expected!='CREATE' and not re.fullmatch(r'(?:DIR-)?[a-f0-9]{64}',expected))):
            raise RuntimeFault('VERSION_REQUIRED','Supply _expected_sha256 from get_file_info.')
        if name=='move_file' and expected=='CREATE':
            raise RuntimeFault('VERSION_REQUIRED','move_file requires the source version token from get_file_info.')
        if name=='list_directory':args['depth']=min(max(int(args.get('depth',2)),1),4)
        if name=='write_pdf':
            if not isinstance(args.get('content'),str) or not args['content'] or len(args['content'])>500000:
                raise RuntimeFault('INVALID_PDF_CONTENT','PDF creation requires bounded Markdown text.')
            if 'outputPath' in args:
                raise RuntimeFault('PDF_OUTPUT_PATH_DISABLED','Use path as the target; outputPath is not qualified.')
            if paths[0].suffix.lower()!='.pdf':
                raise RuntimeFault('INVALID_PDF_PATH','PDF target must end in .pdf.')
        return args,paths,key,expected
    def fingerprint(self,path):
        if not path.exists(): return 'CREATE'
        stat=path.stat()
        if path.is_dir():
            marker=f"{stat.st_dev}:{stat.st_ino}:{stat.st_ctime_ns}:{stat.st_mtime_ns}".encode()
            return 'DIR-'+hashlib.sha256(marker).hexdigest()
        if not path.is_file(): raise RuntimeFault('NOT_FILE','Regular file or directory required.')
        if stat.st_size>32*1024*1024: raise RuntimeFault('FILE_TOO_LARGE','Mutation/hash limit: 32 MiB.')
        with path.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
    def begin(self,owner,project,key,signature):
        with self.connection() as c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT * FROM operations WHERE owner=? AND project=? AND request_key=?',(owner,project,key)).fetchone()
            if row:
                if row['signature']!=signature:raise RuntimeFault('IDEMPOTENCY_CONFLICT','Key already used for a different operation.')
                if row['state']!='DONE':raise RuntimeFault('OPERATION_UNCERTAIN','Previous attempt is running or uncertain. Inspect files; do not replay automatically.')
                return json.loads(row['result'])
            c.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,?)',(owner,project,key,signature,'RUNNING',None,time.time()))
        return None
    def finish(self,owner,project,key,state,result):
        with self.connection() as c:
            c.execute('UPDATE operations SET state=?,result=? WHERE owner=? AND project=? AND request_key=?',(state,json.dumps(result) if result is not None else None,owner,project,key))
    async def call(self,name,args,project,owner):
        mapped,paths,key,expected=self.normalize(name,args,project)
        if name not in WRITE_TOOLS:
            async with self.manager.use('desktop',project,partition=owner) as actor:
                result=await actor.call(name,mapped)
                out=result.model_dump(mode='json',by_alias=True);out.pop('_meta',None)
            if name=='get_file_info':
                eligible=paths[0].is_dir() or (paths[0].is_file() and paths[0].stat().st_size<=32*1024*1024)
                token=await asyncio.to_thread(self.fingerprint,paths[0]) if eligible else None
                out['smart_assistant']={'sha256':token,'version_token':token,'hash_status':'COMPUTED' if eligible else 'NOT_APPLICABLE_OR_OVER_LIMIT','project':project,'path':str(paths[0].relative_to(self.policy.roots[project]))}
            return visible_receipt(out)
        signature=hashlib.sha256(json.dumps({'tool':name,'arguments':mapped,'expected':expected},sort_keys=True).encode()).hexdigest()
        async def perform():
            cached=await asyncio.to_thread(self.begin,owner,project,key,signature)
            if cached is not None:
                cached.setdefault('smart_assistant',{})['idempotent_replay']=True
                return visible_receipt(cached)
            locks=ExitStack()
            chrome_profile=None
            try:
                # Cold backend startup happens before any target FileLock is held.
                async with self.manager.use('desktop',project,partition=owner) as actor:
                    for path in sorted(set(paths),key=lambda p:str(p).casefold()):
                        resource=hashlib.sha256(str(path).casefold().encode()).hexdigest()
                        # FileLock acquisition is non-blocking. Keep enter/close outside
                        # the shared executor so executor starvation cannot extend lock life.
                        locks.enter_context(FileLock(self.filesystem.state_dir/'locks'/resource))
                    if name in {'write_file','edit_block','move_file','write_pdf'}:
                        actual=await asyncio.to_thread(self.fingerprint,paths[0])
                        if actual!=expected:
                            raise RuntimeFault('VERSION_CONFLICT','File changed since inspection.')
                        if paths[0].is_file():
                            raw=await asyncio.to_thread(paths[0].read_bytes)
                            backup=self.root/'file-backups'/(hashlib.sha256(str(paths[0]).casefold().encode()).hexdigest()+'-'+actual)
                            await asyncio.to_thread(atomic_bytes,backup,raw)
                    if name=='move_file' and paths[1].exists():
                        raise RuntimeFault('DESTINATION_EXISTS','No overwrite is performed by move_file.')
                    if name=='write_pdf':
                        chrome_profile=self.chrome_profiles/key
                        await asyncio.to_thread(shutil.rmtree,chrome_profile,True)
                        await asyncio.to_thread(chrome_profile.mkdir,parents=True,exist_ok=True)
                        options=mapped.setdefault('options',{})
                        launch=options.setdefault('launch_options',{})
                        launch['userDataDir']=str(chrome_profile)
                        launch.setdefault('args',['--no-first-run','--disable-background-networking'])
                    try:
                        async with asyncio.timeout(self.backend_call_budget_seconds):
                            result=await actor.call(name,mapped)
                    except asyncio.TimeoutError as exc:
                        raise RuntimeFault('BACKEND_RESULT_UNKNOWN',
                            'Desktop mutation exceeded the bounded backend budget; inspect target before retry.') from exc
                out=result.model_dump(mode='json',by_alias=True)
                out.pop('_meta',None)
                out['smart_assistant']={
                    'request_key':key,'idempotent_replay':False,
                    'backup_preserved':bool(expected and expected!='CREATE' and paths[0].is_file()),
                    'directory_operation':bool(paths[0].is_dir() or
                        (name=='move_file' and expected and expected.startswith('DIR-')))}
                out=visible_receipt(out)
                await asyncio.to_thread(self.finish,owner,project,key,'DONE',out)
                return out
            except BaseException as exc:
                detail={'error':type(exc).__name__,'message':str(exc)[:500]}
                await asyncio.to_thread(self.finish,owner,project,key,'UNKNOWN',detail)
                if isinstance(exc,RuntimeFault):
                    raise
                raise RuntimeFault('COMPATIBILITY_FAILURE',type(exc).__name__+': '+str(exc)[:300]) from exc
            finally:
                locks.close()
                if chrome_profile is not None:
                    await asyncio.to_thread(shutil.rmtree,chrome_profile,True)
        # Network cancellation must not drop mutation locks or trigger a replay.
        task=asyncio.create_task(perform())
        task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
        return await asyncio.shield(task)