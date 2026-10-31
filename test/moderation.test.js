import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createApp} from '../server.js';
import {cipher,normalize} from '../core.js';

test('owner-scoped chat controls validate targets and provider responses',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'bsm-controls-'));
 const env={APP_SECRET:'test-secret-that-is-long-enough-123456',DB_PATH:join(dir,'db'),PUBLIC_URL:'http://localhost:3000'};
 const rt=createApp(env),server=rt.app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 const url='http://127.0.0.1:'+server.address().port;
 const send=(path,cookie,body)=>fetch(url+path,{method:'POST',headers:{'X-BSM-Request':'1','Content-Type':'application/json',...(cookie?{Cookie:cookie}:{})},body:JSON.stringify(body)});
 try{
  const reg=await send('/api/register',null,{email:'mod@example.com',name:'Moderator',password:'a-long-test-password'}),cookie=reg.headers.get('set-cookie').split(';')[0];
  const user=rt.db.prepare('SELECT id FROM users').get().id;
  for(const p of ['twitch','kick'])rt.db.prepare('INSERT INTO connections VALUES(?,?,?,?,?)').run(user,p,'100','owner',cipher(env.APP_SECRET).seal({access_token:'fake',expires:Date.now()+3600000}));
  const tw=normalize('twitch','channel.chat.message',{message_id:'tw-msg',chatter_user_id:'200',chatter_user_name:'Viewer',message:{text:'hello'}});
  const ki=normalize('kick','chat.message.sent',{message_id:'ki-msg',sender:{user_id:300,username:'Viewer'},content:'hello'});
  assert.equal(tw.userId,'200');assert.equal(ki.userId,'300');
  rt.publish(user,tw,'tw');rt.publish(user,ki,'ki');
  const calls=[];rt.providers.http=async(u,o)=>{calls.push({url:u,...o,body:o.body?JSON.parse(o.body):undefined});return u.includes('helix/chat/messages')?{data:[{is_sent:true}]}:u.endsWith('/v1/chat')?{data:{is_sent:true}}:{}};
  const action=(p,b,c=cookie)=>send('/api/chat/'+p+'/action',c,b);
  assert.equal((await action('twitch',{action:'ban',messageId:'tw-msg'},'')).status,401);
  assert.equal((await action('kick',{action:'ban',messageId:'tw-msg'})).status,404);
  assert.equal((await action('twitch',{action:'ban',messageId:'someone-elses-message'})).status,404);
  assert.equal((await action('tiktok',{action:'send',text:'hello'})).status,422);
  assert.equal((await action('twitch',{action:'send',text:' '.repeat(10)})).status,400);
  assert.equal((await action('kick',{action:'timeout',messageId:'ki-msg',duration:0})).status,400);
  assert.equal(calls.length,0);
  assert.equal((await action('twitch',{action:'timeout',messageId:'tw-msg',duration:10,userId:'999',broadcaster_id:'999'})).status,200);
  assert.equal(calls.at(-1).body.data.duration,600);assert.equal(calls.at(-1).body.data.user_id,'200');assert(calls.at(-1).url.includes('broadcaster_id=100'));
  assert.equal((await action('kick',{action:'timeout',messageId:'ki-msg',duration:10})).status,200);
  assert.equal(calls.at(-1).body.duration,10);assert.equal(calls.at(-1).body.user_id,300);
  assert.equal((await action('kick',{action:'unban',messageId:'ki-msg'})).status,200);assert.equal(calls.at(-1).method,'DELETE');
  assert.equal((await action('twitch',{action:'send',messageId:'tw-msg',text:'reply'})).status,200);assert.equal(calls.at(-1).body.reply_parent_message_id,'tw-msg');
  assert.equal((await action('kick',{action:'send',messageId:'ki-msg',text:'reply'})).status,200);assert.equal(calls.at(-1).body.reply_to_message_id,'ki-msg');
  rt.providers.http=async()=>({data:[{is_sent:false}]});
  assert.equal((await action('twitch',{action:'send',text:'rejected'})).status,422);
  rt.providers.http=async()=>{throw Object.assign(Error('forbidden'),{status:403})};
  assert.equal((await action('kick',{action:'delete',messageId:'ki-msg'})).status,502);
  assert(rt.db.prepare('SELECT payload FROM events WHERE event_key=?').get('ki'));
  rt.providers.http=async()=>({});
  assert.equal((await action('kick',{action:'delete',messageId:'ki-msg'})).status,200);
  assert.equal(rt.db.prepare('SELECT payload FROM events WHERE event_key=?').get('ki'),undefined);
  assert(rt.db.prepare('SELECT payload FROM events WHERE event_key=?').get('tw'));
 }finally{rt.close();await new Promise(r=>server.close(r));rmSync(dir,{recursive:true,force:true})}
});
