from __future__ import annotations

import asyncio
import json


class RequestBounds:
    def __init__(self,app,max_inflight=48,max_body=512*1024,body_timeout=10):
        self.app,self.maximum,self.max_body=app,max_inflight,max_body
        self.inflight=0
        self.body_timeout=body_timeout

    async def __call__(self,scope,receive,send):
        if scope['type']!='http':
            return await self.app(scope,receive,send)
        async def reject(code,message):
            body=json.dumps({'error':message}).encode()
            await send({'type':'http.response.start','status':code,'headers':[
                (b'content-type',b'application/json'),(b'cache-control',b'no-store'),(b'retry-after',b'2')]})
            await send({'type':'http.response.body','body':body})
        if self.inflight>=self.maximum:
            return await reject(503,'EDGE_BUSY')
        self.inflight+=1
        try:
            if scope['method']=='POST':
                body=bytearray()
                try:
                    async with asyncio.timeout(self.body_timeout):
                        while True:
                            event=await receive()
                            if event['type']=='http.disconnect': return
                            body.extend(event.get('body',b''))
                            if len(body)>self.max_body: return await reject(413,'BODY_TOO_LARGE')
                            if not event.get('more_body',False): break
                except asyncio.TimeoutError:
                    return await reject(408,'BODY_TIMEOUT')
                pending=True
                async def replay():
                    nonlocal pending
                    if pending:
                        pending=False
                        return {'type':'http.request','body':bytes(body),'more_body':False}
                    return await receive()
                await self.app(scope,replay,send)
            else:
                await self.app(scope,receive,send)
        finally:
            self.inflight-=1
