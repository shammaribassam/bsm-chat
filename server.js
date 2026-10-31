
import express from 'express';
import {emoteImageHosts} from './public/emotes.js';
import {performAction} from './moderation.js';
import helmet from 'helmet';
import {rateLimit} from 'express-rate-limit';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {database,cipher,hash,random,passwordHash,passwordCheck,defaults,cleanSettings,normalize} from './core.js';
import {Providers,specs,oauthParams,exchange,identity,verifyKick} from './providers.js';

export async function createApp(env=process.env){
 const base=(env.PUBLIC_URL||'http://localhost:3000').replace(/\/$/,'');const origin=new URL(base).origin;
 if(!env.APP_SECRET||env.APP_SECRET.length<32)throw Error('Set APP_SECRET to at least 32 random characters');
 if(env.NODE_ENV==='production'&&!base.startsWith('https://'))throw Error('Production PUBLIC_URL must use HTTPS');
 const db=await database(env.DB_PATH||'./data/bsm.sqlite',env),crypt=cipher(env.APP_SECRET);const app=express();app.disable('x-powered-by');app.set('trust proxy',1);
 app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],connectSrc:["'self'"],imgSrc:["'self'","data:",...emoteImageHosts.flatMap(h=>['https://'+h,...(!['static-cdn.jtvnw.net','files.kick.com'].includes(h)?['https://*.'+h]:[])])],frameAncestors:["'none'"],upgradeInsecureRequests:env.NODE_ENV==='production'?[]:null}},strictTransportSecurity:env.NODE_ENV==='production'?undefined:false}));
 app.use((req,res,next)=>{res.set('Referrer-Policy','no-referrer');if(req.path.startsWith('/api/')||req.path.startsWith('/auth/'))res.set('Cache-Control','no-store');next()});
 const listeners=new Map(),states=new Map();
 function broadcast(user,type,data){for(const entry of listeners.get(user)||[])entry.res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`)}
 function status(user,provider,state,detail){if(!states.has(user))states.set(user,{});states.get(user)[provider]={state,detail};broadcast(user,'status',{provider,state,detail})}
 async function publish(user,event,key){const result=await db.prepare('INSERT OR IGNORE INTO events(user_id,event_key,payload,created) VALUES(?,?,?,?)').run(user,key,JSON.stringify(event),Date.now());if(!result.changes)return;broadcast(user,'message',event);await db.prepare('DELETE FROM events WHERE user_id=? AND seq NOT IN (SELECT seq FROM events WHERE user_id=? ORDER BY seq DESC LIMIT 300)').run(user,user)}
 const providers=new Providers({db,crypt,env,publish,status});
 app.post('/webhooks/kick',express.raw({type:'application/json',limit:'256kb'}),async(req,res)=>{
 try{if(!Buffer.isBuffer(req.body))return res.sendStatus(400);const id=req.get('Kick-Event-Message-Id'),stamp=req.get('Kick-Event-Message-Timestamp'),sig=req.get('Kick-Event-Signature');if(!id||id.length>200||!sig||sig.length>2000||!Number.isFinite(Date.parse(stamp))||Math.abs(Date.now()-Date.parse(stamp))>300000)return res.sendStatus(401);let key=await providers.key();if(!verifyKick(key,id,stamp,req.body,sig)){key=await providers.key(true);if(!verifyKick(key,id,stamp,req.body,sig))return res.sendStatus(401)}
 const e=JSON.parse(req.body.toString()),type=req.get('Kick-Event-Type');const rows=await db.prepare("SELECT user_id FROM connections WHERE provider='kick' AND external_id=?").all(String(e.broadcaster?.user_id));
 if(!(await db.prepare('INSERT OR IGNORE INTO deliveries(id,created) VALUES(?,?)').run(id,Date.now())).changes)return res.sendStatus(204);
 for(const row of rows){const event=normalize('kick',type,e);if(event)await publish(row.user_id,event,'kick:'+id);status(row.user_id,'kick','connected','أحداث كيك متصلة')}
 res.sendStatus(204)}catch{res.sendStatus(503)}});
 app.use(express.json({limit:'16kb'}));
 app.use(['/api','/auth'],rateLimit({windowMs:60000,limit:180,standardHeaders:'draft-8',legacyHeaders:false,message:{error:'طلبات كثيرة؛ حاول بعد دقيقة'}}));
 app.use((req,res,next)=>{if(['POST','PUT','PATCH','DELETE'].includes(req.method)&&!req.path.startsWith('/webhooks/')){if(req.get('X-BSM-Request')!=='1'||(req.get('Origin')&&req.get('Origin')!==origin))return res.status(403).json({error:'طلب غير مسموح'})}next()});
 const cookieName=env.NODE_ENV==='production'?'__Host-bsm':'bsm';
 async function session(req){let raw='';for(const part of (req.headers.cookie||'').split(';')){const [k,...v]=part.trim().split('=');if(k===cookieName)raw=v.join('=')}if(!raw)return null;const token=hash(raw);const row=await db.prepare('SELECT users.*,sessions.token AS session_hash FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?').get(token,Date.now());return row||null}
 async function auth(req,res,next){req.user=await session(req);if(!req.user)return res.status(401).json({error:'سجل دخولك أولًا'});next()}
 async function setSession(res,user){const token=random();await db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(hash(token),user,Date.now()+7*86400000);res.cookie(cookieName,token,{httpOnly:true,secure:env.NODE_ENV==='production',sameSite:'lax',path:'/',maxAge:7*86400000})}
 const authLimiter=rateLimit({windowMs:900000,limit:20,standardHeaders:'draft-8',legacyHeaders:false,message:{error:'محاولات كثيرة؛ حاول لاحقًا'}});
 app.get('/healthz',async(req,res)=>{await db.prepare('SELECT 1').get();res.json({ok:true})});
 app.post('/api/register',authLimiter,async(req,res)=>{if(env.ALLOW_REGISTRATION==='false')return res.status(403).json({error:'التسجيل مغلق حاليًا'});const {email,password,name}=req.body||{};if(typeof email!=='string'||!/^\S+@\S+\.\S+$/.test(email)||email.length>254||typeof password!=='string'||password.length<8||password.length>128||typeof name!=='string'||!name.trim()||name.length>60)return res.status(400).json({error:'أدخل اسمًا وبريدًا صحيحًا وكلمة مرور من 8 إلى 128 حرفًا'});const id=crypto.randomUUID(),overlay=random(),pass=await passwordHash(password);try{await db.prepare('INSERT INTO users(id,email,name,password,overlay_hash,overlay_secret,created) VALUES(?,?,?,?,?,?,?)').run(id,email.toLowerCase().trim(),name.trim(),pass,hash(overlay),crypt.seal(overlay),Date.now());await setSession(res,id);res.status(201).json({ok:true})}catch{return res.status(409).json({error:'تعذّر إنشاء الحساب؛ جرّب بريدًا آخر'})}});
 const dummy=passwordHash(random());
 app.post('/api/login',authLimiter,async(req,res)=>{const {email,password}=req.body||{};if(typeof email!=='string'||typeof password!=='string'||password.length>128)return res.status(400).json({error:'بيانات غير صحيحة'});const row=await db.prepare('SELECT * FROM users WHERE email=?').get(email.toLowerCase().trim());const valid=await passwordCheck(password,row?.password||await dummy);if(!row||!valid)return res.status(401).json({error:'البريد أو كلمة المرور غير صحيحة'});await setSession(res,row.id);res.json({ok:true})});
 app.post('/api/logout',auth,async(req,res)=>{await db.prepare('DELETE FROM sessions WHERE token=?').run(req.user.session_hash);for(const entry of listeners.get(req.user.id)||[])if(entry.session===req.user.session_hash)entry.res.end();res.clearCookie(cookieName,{path:'/',secure:env.NODE_ENV==='production',httpOnly:true,sameSite:'lax'});res.json({ok:true})});
 const ready=p=>Boolean(env[p.toUpperCase()+'_CLIENT_ID']&&env[p.toUpperCase()+'_CLIENT_SECRET']);
 app.get('/api/me',auth,async(req,res)=>{const rows=await db.prepare('SELECT provider,channel FROM connections WHERE user_id=?').all(req.user.id);const connections={};for(const row of rows)connections[row.provider]={channel:row.channel,...(states.get(req.user.id)?.[row.provider]||{state:'saved',detail:'محفوظ؛ أعد الاتصال'})};res.json({name:req.user.name,email:req.user.email,connections,settings:{...defaults,...JSON.parse(req.user.settings)},overlay:base+'/overlay.html#'+crypt.open(req.user.overlay_secret),capabilities:{twitch:ready('twitch'),kick:ready('kick'),tiktok:env.ENABLE_TIKTOK==='true'}})});
 app.post('/api/chat/:provider/action',auth,async(req,res)=>{
  const p=req.params.provider,input=req.body||{};
  if(!['twitch','kick','tiktok'].includes(p)||!['send','delete','timeout','ban','unban'].includes(input.action))return res.status(400).json({error:'إجراء غير صالح'});
  if(p==='tiktok')return res.status(422).json({error:'موصل تيك توك الحالي للاستقبال فقط؛ الإدارة من تطبيق تيك توك'});
  const {action}=input;
  if(action==='send'&&(typeof input.text!=='string'||!input.text.trim()||input.text.length>500))return res.status(400).json({error:'اكتب رسالة من 1 إلى 500 حرف'});
  if(action==='timeout'&&(!Number.isInteger(input.duration)||input.duration<1||input.duration>10080))return res.status(400).json({error:'مدة التايم أوت من دقيقة إلى 10080 دقيقة'});
  if(input.reason!==undefined&&(typeof input.reason!=='string'||input.reason.length>100))return res.status(400).json({error:'السبب بحد أقصى 100 حرف'});
  let message;
  if(action!=='send'||input.messageId){
   message=(await db.prepare('SELECT payload FROM events WHERE user_id=? ORDER BY seq DESC LIMIT 300').all(req.user.id)).map(r=>JSON.parse(r.payload)).find(m=>m.provider===p&&m.id===input.messageId&&m.kind==='chat');
   if(!message)return res.status(404).json({error:'الرسالة غير متاحة في سجل حسابك'});
   if(['ban','timeout','unban'].includes(action)&&!/^\d+$/.test(message.userId||''))return res.status(422).json({error:'هذه رسالة قديمة دون معرّف المستخدم؛ اختر رسالة جديدة'});
  }
  try{
   await performAction(providers,req.user.id,p,{...input,text:input.text?.trim(),reason:input.reason||'',message});
   if(action==='delete'){
    for(const row of await db.prepare('SELECT seq,payload FROM events WHERE user_id=?').all(req.user.id)){
     const event=JSON.parse(row.payload);if(event.provider===p&&event.id===message.id)await db.prepare('DELETE FROM events WHERE seq=? AND user_id=?').run(row.seq,req.user.id);
    }
    broadcast(req.user.id,'removed',{provider:p,id:message.id});
   }
   res.json({ok:true});
  }catch(e){const known=[409,422].includes(e.status);res.status(known?e.status:502).json({error:known?e.message:e.status===401||e.status===403?'رفضت المنصة الصلاحية؛ أعد تفويض الحساب من ربط المنصات':'تعذّر تنفيذ الإجراء لدى المنصة؛ تحقق من الاتصال وحالة المستخدم ثم أعد المحاولة'});}
 });
 app.put('/api/settings',auth,async(req,res)=>{const settings={...defaults,...JSON.parse(req.user.settings),...cleanSettings(req.body||{})};await db.prepare('UPDATE users SET settings=? WHERE id=?').run(JSON.stringify(settings),req.user.id);broadcast(req.user.id,'settings',settings);res.json(settings)});
 app.post('/api/overlay/rotate',auth,async(req,res)=>{const token=random();await db.prepare('UPDATE users SET overlay_hash=?,overlay_secret=? WHERE id=?').run(hash(token),crypt.seal(token),req.user.id);for(const entry of listeners.get(req.user.id)||[])if(entry.overlay)entry.res.end();res.json({url:base+'/overlay.html#'+token})});
 async function overlayUser(req){const key=req.get('Authorization')?.replace(/^Bearer /,'');if(!key||key.length>100)return null;return await db.prepare('SELECT * FROM users WHERE overlay_hash=?').get(hash(key))}
 async function history(user){return (await db.prepare('SELECT payload FROM events WHERE user_id=? AND created>? ORDER BY seq DESC LIMIT 100').all(user,Date.now()-86400000)).reverse().map(r=>JSON.parse(r.payload))}
 async function stream(req,res,user,overlay=false){if((listeners.get(user.id)?.size||0)>=10)return res.status(429).json({error:'عدد نوافذ العرض وصل للحد الأقصى'});res.set({'Content-Type':'text/event-stream','Cache-Control':'no-store','Connection':'keep-alive','X-Accel-Buffering':'no'});res.flushHeaders();const entry={res,session:user.session_hash,overlay};if(!listeners.has(user.id))listeners.set(user.id,new Set());listeners.get(user.id).add(entry);res.write('event: initial\ndata: '+JSON.stringify({messages:await history(user.id),settings:{...defaults,...JSON.parse(user.settings)}})+'\n\n');const heartbeat=setInterval(async()=>{try{if(res.writableEnded)return;if(!overlay&&!(await db.prepare('SELECT 1 FROM sessions WHERE token=? AND expires>?').get(entry.session,Date.now())))return res.end();if(res.writableLength>1024*1024)return res.end();res.write(': heartbeat\n\n')}catch{res.end()}},20000);heartbeat.unref();res.on('close',()=>{clearInterval(heartbeat);listeners.get(user.id)?.delete(entry);if(!listeners.get(user.id)?.size)listeners.delete(user.id)})}
 app.get('/api/events',auth,async(req,res)=>stream(req,res,req.user));
 app.get('/api/overlay/events',async(req,res)=>{const user=await overlayUser(req);if(!user)return res.sendStatus(401);await stream(req,res,user,true)});
 app.post('/api/connections/tiktok',auth,async(req,res)=>{if(env.ENABLE_TIKTOK!=='true')return res.status(503).json({error:'موصل تيك توك التجريبي غير مفعّل بالخادم'});const channel=String(req.body?.channel||'').replace(/^@/,'').trim();if(!/^[\w.]{2,50}$/.test(channel))return res.status(400).json({error:'اسم قناة غير صحيح'});try{await db.prepare('INSERT INTO connections VALUES(?,?,?,?,?) ON CONFLICT(user_id,provider) DO UPDATE SET external_id=excluded.external_id,channel=excluded.channel,secret=excluded.secret').run(req.user.id,'tiktok',channel.toLowerCase(),channel,crypt.seal({}));void providers.start(req.user.id,'tiktok');res.json({ok:true})}catch{res.status(409).json({error:'القناة مرتبطة بحساب آخر'})}});
 app.post('/api/connections/:provider/reconnect',auth,async(req,res)=>{const p=req.params.provider;if(!['twitch','kick','tiktok'].includes(p)||!(await providers.row(req.user.id,p)))return res.status(404).json({error:'اربط القناة أولًا'});void providers.start(req.user.id,p).catch(()=>status(req.user.id,p,'error','تعذّر الاتصال'));res.json({ok:true})});
 app.delete('/api/connections/:provider',auth,async(req,res)=>{const p=req.params.provider;if(!['twitch','kick','tiktok'].includes(p))return res.sendStatus(404);if(p==='kick'){try{await providers.disconnectKick(req.user.id)}catch{return res.status(502).json({error:'تعذّر إلغاء أحداث كيك لدى المنصة؛ أعد المحاولة'})}}providers.stop(req.user.id,p);await db.prepare('DELETE FROM connections WHERE user_id=? AND provider=?').run(req.user.id,p);status(req.user.id,p,'disconnected','غير متصل');res.json({ok:true})});
 app.get('/auth/:provider',auth,async(req,res)=>{const p=req.params.provider;if(!specs[p]||!ready(p))return res.status(503).send('مفاتيح تطبيق المنصة غير مضبوطة بالخادم');const state=random(),verifier=random();await db.prepare('INSERT INTO oauth VALUES(?,?,?,?,?,?)').run(hash(state),req.user.id,p,verifier,req.user.session_hash,Date.now()+600000);const params={response_type:'code',client_id:oauthParams(p,env).client_id,redirect_uri:base+'/auth/'+p+'/callback',state,scope:specs[p].scope};if(p==='kick'){params.code_challenge=crypto.createHash('sha256').update(verifier).digest('base64url');params.code_challenge_method='S256'}res.redirect(specs[p].authorize+'?'+new URLSearchParams(params))});
 app.get('/auth/:provider/callback',auth,async(req,res)=>{const p=req.params.provider,state=String(req.query.state||'');const row=await db.prepare('SELECT * FROM oauth WHERE state=?').get(hash(state));if(!specs[p]||!row||row.user_id!==req.user.id||row.provider!==p||row.session_hash!==req.user.session_hash||row.expires<Date.now())return res.status(400).send('طلب الربط غير صالح أو انتهت صلاحيته');await db.prepare('DELETE FROM oauth WHERE state=?').run(hash(state));if(req.query.error||typeof req.query.code!=='string')return res.redirect('/?notice=denied');try{const token=await exchange(p,env,{grant_type:'authorization_code',code:req.query.code,redirect_uri:base+'/auth/'+p+'/callback',...(p==='kick'?{code_verifier:row.verifier}:{})});const who=await identity(p,env,token.access_token);const data={...token,expires:Date.now()+Number(token.expires_in)*1000};await db.prepare('INSERT INTO connections VALUES(?,?,?,?,?) ON CONFLICT(user_id,provider) DO UPDATE SET external_id=excluded.external_id,channel=excluded.channel,secret=excluded.secret').run(req.user.id,p,who.id,who.name,crypt.seal(data));void providers.start(req.user.id,p).catch(()=>status(req.user.id,p,'error','تعذّر الاتصال'));res.redirect('/?notice=linked')}catch{res.redirect('/?notice=failed')}});
 app.use(express.static(fileURLToPath(new URL('./public/',import.meta.url)),{index:'index.html',maxAge:0}));
 app.use((error,req,res,next)=>{if(res.headersSent)return next(error);res.status(error.status===400?400:500).json({error:error.status===400?'طلب غير صالح':'تعذّر إتمام الطلب'})});
 const cleanup=setInterval(async()=>{try{const now=Date.now();await db.prepare('DELETE FROM sessions WHERE expires<?').run(now);await db.prepare('DELETE FROM oauth WHERE expires<?').run(now);await db.prepare('DELETE FROM deliveries WHERE created<?').run(now-86400000);await db.prepare('DELETE FROM events WHERE created<?').run(now-86400000)}catch(error){console.error('Database cleanup failed:',error)}},60000);cleanup.unref();
 async function restore(){for(const row of await db.prepare('SELECT user_id,provider FROM connections').all()){await providers.start(row.user_id,row.provider).catch(()=>status(row.user_id,row.provider,'error','تعذّر استعادة الاتصال'))}}
 function close(){clearInterval(cleanup);providers.close();for(const entries of listeners.values())for(const e of entries)e.res.end();db.close()}
 return {app,db,providers,publish,close,restore};
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){const runtime=await createApp();const server=runtime.app.listen(Number(process.env.PORT||process.argv[process.argv.indexOf('--port')+1])||3000,'0.0.0.0',()=>{console.log('BSM Chat server ready');void runtime.restore()});for(const signal of ['SIGTERM','SIGINT'])process.once(signal,()=>{runtime.close();server.close(()=>process.exit(0));setTimeout(()=>process.exit(0),5000).unref()})}
