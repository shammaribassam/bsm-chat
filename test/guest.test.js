import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createApp} from '../server.js';
import {parseIRC,startKickReader} from '../public-readers.js';

test('anonymous spaces reuse only their own cookie and allow the same public channel independently',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'bsm-guest-')),rt=createApp({APP_SECRET:'test-guest-secret-long-enough-12345678',DB_PATH:join(dir,'db'),PUBLIC_URL:'http://localhost:3000',ENABLE_TIKTOK:'true'});
 rt.providers.start=async()=>{};
 const server=rt.app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));const base='http://127.0.0.1:'+server.address().port;
 const post=(path,cookie,body={})=>fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json','X-BSM-Request':'1',...(cookie?{Cookie:cookie}:{})},body:JSON.stringify(body)});
 try{
  const a=await post('/api/guest'),b=await post('/api/guest');assert.equal(a.status,201);assert.equal(b.status,201);
  const ca=a.headers.get('set-cookie').split(';')[0],cb=b.headers.get('set-cookie').split(';')[0];assert.notEqual(ca,cb);
  assert.equal((await post('/api/guest',ca)).status,200);assert.equal(rt.db.prepare('SELECT COUNT(*) AS n FROM users').get().n,2);
  for(const c of [ca,cb])assert.equal((await post('/api/public-connect',c,{provider:'twitch',channel:'same_channel'})).status,200);
  assert.equal(rt.db.prepare('SELECT COUNT(*) AS n FROM public_readers WHERE channel=?').get('same_channel').n,2);
  const me=async c=>(await fetch(base+'/api/me',{headers:{Cookie:c}})).json();
  const one=await me(ca),two=await me(cb);assert.notEqual(one.overlay,two.overlay);assert.equal(one.connections.twitch.mode,'read');
  assert.equal((await post('/api/public-connect',ca,{provider:'twitch',channel:'bad\r\nJOIN #other'})).status,400);
  assert.equal((await post('/api/public-connect',null,{provider:'twitch',channel:'other'})).status,401);
  assert.equal((await post('/api/chat/twitch/action',ca,{action:'send',text:'unauthorized'})).status,409);
  await fetch(base+'/api/connections/twitch',{method:'DELETE',headers:{Cookie:ca,'X-BSM-Request':'1'}});
  assert.equal((await me(ca)).connections.twitch,undefined);assert.equal((await me(cb)).connections.twitch.channel,'same_channel');
 }finally{rt.close();await new Promise(r=>server.close(r));rmSync(dir,{recursive:true,force:true})}
});

test('IRC parser preserves text, ids and escaped display names',()=>{
 const m=parseIRC('@display-name=First\\sLast;id=message-1;user-id=42 :viewer!viewer@host PRIVMSG #channel :hello : world');
 assert.equal(m.tags['display-name'],'First Last');assert.equal(m.tags.id,'message-1');assert.equal(m.text,'hello : world');assert.equal(m.params[0],'#channel');assert.equal(parseIRC('PING :tmi.twitch.tv').command,'PING');
});

test('Kick channel-name connection uses app token and broadcaster-specific webhook subscriptions',async()=>{
 const calls=[],states=[];let resolved;
 const manager={env:{KICK_CLIENT_ID:'test',KICK_CLIENT_SECRET:'test'},active:new Map(),status:(...x)=>states.push(x),db:{prepare:()=>({run:(...x)=>resolved=x})},http:async(url,options)=>{
  calls.push({url,options});if(url.endsWith('/oauth/token'))return {access_token:'app-test-token',expires_in:3600};
  if(url.includes('/channels?'))return {data:[{slug:'channel',broadcaster_user_id:123}]};
  return {data:[]};
 }};
 await startKickReader(manager,{user_id:'visitor',channel:'channel'});
 assert.equal(resolved[0],'123');const sub=calls.find(x=>x.options.method==='POST'&&x.url.includes('/events/subscriptions'));
 assert.equal(JSON.parse(sub.options.body).broadcaster_user_id,123);assert.equal(states.at(-1)[2],'waiting');
});
