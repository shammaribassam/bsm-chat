import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createApp} from '../server.js';
import {cipher,normalize,hash} from '../core.js';
import {verifyKick} from '../providers.js';
const dir=mkdtempSync(join(tmpdir(),'bsm-test-'));
const env={APP_SECRET:'unit-test-secret-at-least-32-characters',DB_PATH:join(dir,'db.sqlite'),PUBLIC_URL:'http://localhost:3000',NODE_ENV:'test',TWITCH_CLIENT_ID:'fake-client-id',TWITCH_CLIENT_SECRET:'fake-client-secret'};
const rt=await createApp(env),server=rt.app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base='http://127.0.0.1:'+server.address().port;
after(async()=>{await rt.close();await new Promise(resolve=>server.close(resolve));rmSync(dir,{recursive:true,force:true})});
async function req(path,{cookie,method='GET',body,headers={}}={}){const res=await fetch(base+path,{method,headers:{'X-BSM-Request':'1','Content-Type':'application/json',...(cookie?{Cookie:cookie}:{}),...headers},...(body?{body:JSON.stringify(body)}:{}),redirect:'manual'});let data;try{data=await res.clone().json()}catch{}return {res,data,cookie:res.headers.get('set-cookie')?.split(';')[0]}}
const password='test-passphrase-12345';let a,b,aid,bid;
test('register two accounts and reject invalid credentials',async()=>{a=await req('/api/register',{method:'POST',body:{email:'one@example.com',name:'واحد',password}});b=await req('/api/register',{method:'POST',body:{email:'two@example.com',name:'اثنين',password}});assert.equal(a.res.status,201);assert.equal(b.res.status,201);const bad=await req('/api/login',{method:'POST',body:{email:'one@example.com',password:'incorrect-password'}});assert.equal(bad.res.status,401);const invalid=await req('/api/register',{method:'POST',body:{email:'bad',name:'x',password:'short'}});assert.equal(invalid.res.status,400);aid=(await rt.db.prepare('SELECT id FROM users WHERE email=?').get('one@example.com')).id;bid=(await rt.db.prepare('SELECT id FROM users WHERE email=?').get('two@example.com')).id});
test('API requires login and rejects cross-origin mutations',async()=>{assert.equal((await req('/api/me')).res.status,401);assert.equal((await req('/api/settings',{method:'PUT',cookie:a.cookie,headers:{Origin:'https://attacker.example'},body:{accent:'#ff0000'}})).res.status,403)});
test('settings are isolated and sanitized',async()=>{await req('/api/settings',{method:'PUT',cookie:a.cookie,body:{accent:'#ff0000',fontSize:99,chat:false,unknown:'x'}});const one=(await req('/api/me',{cookie:a.cookie})).data,two=(await req('/api/me',{cookie:b.cookie})).data;assert.equal(one.settings.accent,'#ff0000');assert.equal(one.settings.fontSize,18);assert.equal(one.settings.chat,false);assert.equal(two.settings.chat,true);assert.equal(two.settings.accent,'#b9f76c');assert.equal(one.settings.unknown,undefined);assert(!JSON.stringify(one).includes('password'));assert(!JSON.stringify(one).includes('fake-client-secret'))});
test('stream is isolated, deduplicated and overlay token is revocable',async()=>{await rt.publish(aid,{id:'one',provider:'twitch',kind:'chat',name:'x',text:'private one',time:Date.now()},'event-one');await rt.publish(aid,{id:'one',text:'duplicate'},'event-one');await rt.publish(bid,{id:'two',provider:'kick',kind:'chat',name:'y',text:'private two',time:Date.now()},'event-two');const me=(await req('/api/me',{cookie:a.cookie})).data;const key=new URL(me.overlay).hash.slice(1);const abort=new AbortController();const r=await fetch(base+'/api/overlay/events',{headers:{Authorization:'Bearer '+key},signal:abort.signal});const reader=r.body.getReader();const text=new TextDecoder().decode((await reader.read()).value);assert(text.includes('private one'));assert(!text.includes('private two'));assert(!text.includes('duplicate'));abort.abort();const rotation=await req('/api/overlay/rotate',{method:'POST',cookie:a.cookie});assert.notEqual(rotation.data.url,me.overlay);const old=await fetch(base+'/api/overlay/events',{headers:{Authorization:'Bearer '+key}});assert.equal(old.status,401);const unauthorized=await fetch(base+'/api/overlay/events?token='+key);assert.equal(unauthorized.status,401)});
test('OAuth state is session-bound, single-use and expires',async()=>{const start=await req('/auth/twitch',{cookie:a.cookie});assert.equal(start.res.status,302);const oauth=new URL(start.res.headers.get('location'));const state=oauth.searchParams.get('state');assert(state.length>40);const stored=await rt.db.prepare('SELECT * FROM oauth WHERE state=?').get(hash(state));await rt.db.prepare('INSERT INTO oauth VALUES(?,?,?,?,?,?)').run(hash('expired-state'),stored.user_id,stored.provider,stored.verifier,stored.session_hash,Date.now()-1);assert.equal((await req('/auth/twitch/callback?state=expired-state&error=denied',{cookie:a.cookie})).res.status,400);const stolen=await req('/auth/twitch/callback?state='+state+'&error=denied',{cookie:b.cookie});assert.equal(stolen.res.status,400);const correct=await req('/auth/twitch/callback?state='+state+'&error=denied',{cookie:a.cookie});assert.equal(correct.res.status,302);assert.equal((await req('/auth/twitch/callback?state='+state+'&error=denied',{cookie:a.cookie})).res.status,400)});
test('encrypted tokens do not expose plaintext and reject tampering',()=>{const c=cipher(env.APP_SECRET);const sealed=c.seal({access_token:'sensitive'});assert(!sealed.includes('sensitive'));assert.equal(c.open(sealed).access_token,'sensitive');assert.throws(()=>cipher('different-secret').open(sealed))});
test('Kick webhook signatures require authentic raw body and recent timestamp',()=>{const {publicKey,privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});const stamp=new Date().toISOString(),body=Buffer.from('{"test":1}'),id='event-123';const sig=crypto.sign('RSA-SHA256',Buffer.concat([Buffer.from(id+'.'+stamp+'.'),body]),privateKey).toString('base64');assert(verifyKick(publicKey,id,stamp,body,sig));assert(!verifyKick(publicKey,id,stamp,Buffer.from('{}'),sig));assert(!verifyKick(publicKey,id,stamp,body,sig,Date.now()+600000));assert(!verifyKick(publicKey,id,'bad-date',body,sig))});
test('normalization covers gifts without double-counting Twitch gift recipients or TikTok streaks',()=>{assert.equal(normalize('twitch','channel.subscribe',{is_gift:true}),null);assert.equal(normalize('tiktok','gift',{giftType:1,repeatEnd:false}),null);assert.equal(normalize('tiktok','gift',{giftDetails:{giftType:1},repeatEnd:false}),null);assert.equal(normalize('tiktok','gift',{giftType:1,repeatEnd:true,repeatCount:5,giftName:'Rose'}).count,5);assert.equal(normalize('kick','channel.subscription.gifts',{gifter:{username:'gifter'},giftees:[{},{}]}).count,2);assert.equal(normalize('kick','chat.message.sent',{sender:{username:'a'},content:'<script>alert(1)</script>'}).text,'<script>alert(1)</script>')});
test('restart retains accounts/settings and does not store raw session keys',async()=>{const token=a.cookie.split('=')[1];assert.equal(await rt.db.prepare('SELECT * FROM sessions WHERE token=?').get(token),undefined);assert(await rt.db.prepare('SELECT * FROM sessions WHERE token=?').get(hash(token)));const second=await createApp(env);assert.equal((await second.db.prepare('SELECT name FROM users WHERE id=?').get(aid)).name,'واحد');await second.close()});
test('logout invalidates the session',async()=>{assert.equal((await req('/api/logout',{method:'POST',cookie:a.cookie})).res.status,200);assert.equal((await req('/api/me',{cookie:a.cookie})).res.status,401)});

test('signed Kick webhook routes only to channel owner and rejects forgery/replay',async()=>{
 const {publicKey,privateKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
 rt.providers.kickKey={key:publicKey,expires:Date.now()+3600000};
 await rt.db.prepare('INSERT INTO connections VALUES(?,?,?,?,?)').run(bid,'kick','999','test-channel',cipher(env.APP_SECRET).seal({}));
 const stamp=new Date().toISOString(),id='signed-webhook-123',raw=JSON.stringify({broadcaster:{user_id:999},sender:{username:'viewer'},content:'signed test message'});
 const sig=crypto.sign('RSA-SHA256',Buffer.from(id+'.'+stamp+'.'+raw),privateKey).toString('base64');
 const headers={'Content-Type':'application/json','Kick-Event-Message-Id':id,'Kick-Event-Message-Timestamp':stamp,'Kick-Event-Signature':sig,'Kick-Event-Type':'chat.message.sent'};
 const send=()=>fetch(base+'/webhooks/kick',{method:'POST',headers,body:raw});
 assert.equal((await send()).status,204);assert.equal((await send()).status,204);
 assert.equal((await rt.db.prepare('SELECT COUNT(*) AS n FROM events WHERE event_key=? AND user_id=?').get('kick:'+id,bid)).n,1);
 assert.equal((await rt.db.prepare('SELECT COUNT(*) AS n FROM events WHERE event_key=? AND user_id=?').get('kick:'+id,aid)).n,0);
 // Stale but otherwise valid signatures must be rejected before obtaining an external key.
 const stale=new Date(Date.now()-600000).toISOString();
 const staleSig=crypto.sign('RSA-SHA256',Buffer.from(id+'.'+stale+'.'+raw),privateKey).toString('base64');
 const original=rt.providers.key.bind(rt.providers);rt.providers.key=async()=>publicKey;
 try{assert.equal((await fetch(base+'/webhooks/kick',{method:'POST',headers:{...headers,'Kick-Event-Message-Timestamp':stale,'Kick-Event-Signature':staleSig},body:raw})).status,401)}finally{rt.providers.key=original}
});

test('display aggregation keeps platforms and streamers separate and obeys settings',async()=>{
 const {aggregate,allowed}=await import('../public/shared.js');
 const m={id:'a',provider:'tiktok',kind:'like',name:'same',text:'أرسل 2 قلبًا ❤️',count:2,time:1000};
 const result=aggregate([m,{...m,id:'b',count:3,time:1500},{...m,id:'c',name:'different',time:1600},{...m,id:'d',provider:'twitch',time:1700}]);
 assert.equal(result.length,3);assert.equal(result[0].count,5);assert.equal(m.count,2);
 assert(!allowed(m,{like:false}));assert(!allowed({...m,text:'badword'},{blockedWords:'badword'}));assert(allowed(m,{like:true}));
});
