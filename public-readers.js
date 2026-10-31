import WebSocket from 'ws';
import crypto from 'node:crypto';
import {normalize} from './core.js';

export function parseIRC(line){
 const tags={};let rest=line;
 if(rest.startsWith('@')){const end=rest.indexOf(' ');for(const pair of rest.slice(1,end).split(';')){const i=pair.indexOf('=');tags[pair.slice(0,i)]=pair.slice(i+1).replace(/\\([s:nr\\])/g,(_,c)=>({s:' ',':':';',n:'\n',r:'\r','\\':'\\'}[c]))}rest=rest.slice(end+1)}
 let prefix='';if(rest.startsWith(':')){const end=rest.indexOf(' ');prefix=rest.slice(1,end);rest=rest.slice(end+1)}
 const i=rest.indexOf(' :'),text=i<0?'':rest.slice(i+2),parts=(i<0?rest:rest.slice(0,i)).split(' ');
 return {tags,prefix,command:parts[0],params:parts.slice(1),text};
}

export function startTwitchReader(manager,row){
 const user=row.user_id,key=user+':twitch',h={stopped:false,sockets:new Set(),attempt:0};manager.active.set(key,h);
 const status=(state,detail)=>manager.status(user,'twitch',state,detail);
 function dial(){
  if(h.stopped)return;status('connecting','جاري استقبال الشات باسم القناة');
  const socket=new WebSocket('wss://irc-ws.chat.twitch.tv:443',{handshakeTimeout:15000});h.sockets.add(socket);
  let joined=false;
  const watch=()=>{clearTimeout(h.watch);h.watch=setTimeout(()=>socket.terminate(),330000);h.watch.unref()};
  socket.on('open',()=>{watch();socket.send('CAP REQ :twitch.tv/tags twitch.tv/commands\r\nPASS SCHMOOPIIE\r\nNICK justinfan'+crypto.randomInt(100000,999999999)+'\r\nJOIN #'+row.channel+'\r\n')});
  socket.on('error',()=>{});
  socket.on('message',raw=>{watch();for(const line of raw.toString().split('\r\n').filter(Boolean)){
   const m=parseIRC(line),t=m.tags;
   if(m.command==='PING'){socket.send('PONG :'+m.text+'\r\n');continue}
   if(m.command==='RECONNECT'){socket.close();continue}
   if((['ROOMSTATE','JOIN'].includes(m.command)&&m.params[0]==='#'+row.channel)||(m.command==='366'&&m.params.includes('#'+row.channel))){joined=true;h.attempt=0;status('connected','متصل بالشات العام • استقبال فقط')}
   if(m.command==='NOTICE'&&!joined)status('error','رفض تويتش الاتصال بهذه القناة؛ تحقق من الاسم أو استخدم التفويض الاختياري');
   if(m.command==='PRIVMSG'&&m.params[0]==='#'+row.channel){
    const event=normalize('twitch','channel.chat.message',{message_id:t.id,chatter_user_id:t['user-id'],chatter_user_name:t['display-name']||m.prefix.split('!')[0],message:{text:m.text}});
    manager.publish(user,event,'twitch:'+event.id);
   }
   if(m.command==='USERNOTICE'&&m.params[0]==='#'+row.channel){
    const type=t['msg-id'];let event;
    const common={message_id:t.id,user_name:t['display-name']||t.login};
    if(['sub','resub'].includes(type))event=normalize('twitch',type==='sub'?'channel.subscribe':'channel.subscription.message',{...common,cumulative_months:Number(t['msg-param-cumulative-months'])});
    if(type==='submysterygift')event=normalize('twitch','channel.subscription.gift',{...common,total:Number(t['msg-param-mass-gift-count'])});
    if(type==='raid')event=normalize('twitch','channel.raid',{...common,viewers:Number(t['msg-param-viewerCount'])});
    if(event)manager.publish(user,event,'twitch:'+event.id);
   }
  }});
  socket.on('close',()=>{h.sockets.delete(socket);clearTimeout(h.watch);if(h.stopped)return;status('reconnecting','انقطع الشات؛ تجري إعادة الاتصال');h.retry=setTimeout(dial,Math.min(60000,3000*2**Math.min(h.attempt++,4)));h.retry.unref()});
 }
 dial();
}

export async function kickAppToken(manager){
 if(manager.appKick?.expires>Date.now()+60000)return manager.appKick.token;
 if(manager.appKickPending)return manager.appKickPending;
 if(!manager.env.KICK_CLIENT_ID||!manager.env.KICK_CLIENT_SECRET)throw Error('kick_app_missing');
 manager.appKickPending=(async()=>{const d=await manager.http('https://id.kick.com/oauth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'client_credentials',client_id:manager.env.KICK_CLIENT_ID,client_secret:manager.env.KICK_CLIENT_SECRET})});if(!d.access_token)throw Error('no_token');manager.appKick={token:d.access_token,expires:Date.now()+Number(d.expires_in||3600)*1000};return d.access_token})();
 try{return await manager.appKickPending}finally{manager.appKickPending=null}
}

export async function startKickReader(manager,row){
 const user=row.user_id,key=user+':kick',h={stopped:false};manager.active.set(key,h);
 manager.status(user,'kick','connecting','جاري الاشتراك بالشات باسم القناة');
 try{
  const token=await kickAppToken(manager),headers={Authorization:'Bearer '+token,'Content-Type':'application/json'};
  const channels=await manager.http('https://api.kick.com/public/v1/channels?slug='+encodeURIComponent(row.channel),{headers});
  const channel=channels.data?.find(c=>c.slug?.toLowerCase()===row.channel);
  if(!channel?.broadcaster_user_id)throw Error('no_channel');
  if(h.stopped)return;
  const id=String(channel.broadcaster_user_id);
  manager.db.prepare("UPDATE public_readers SET external_id=? WHERE user_id=? AND provider='kick' AND channel=?").run(id,user,row.channel);
  const existing=await manager.http('https://api.kick.com/public/v1/events/subscriptions?broadcaster_user_id='+id,{headers});
  const types=['chat.message.sent','channel.followed','channel.subscription.new','channel.subscription.renewal','channel.subscription.gifts'];
  const known=new Set((existing.data||[]).filter(s=>String(s.broadcaster_user_id)===id).map(s=>s.event));
  const missing=types.filter(t=>!known.has(t));let failed=0;
  if(missing.length){const d=await manager.http('https://api.kick.com/public/v1/events/subscriptions',{method:'POST',headers,body:JSON.stringify({broadcaster_user_id:Number(id),method:'webhook',events:missing.map(name=>({name,version:1}))})});failed=(d.data||[]).filter(x=>x.error).length;}
  if(!h.stopped)manager.status(user,'kick',failed?'partial':'waiting',failed?'تعذّر تفعيل بعض التفاعلات؛ تحقق من إعداد تطبيق كيك':'تم الاشتراك • بانتظار أول رسالة');
 }catch(e){if(!h.stopped)manager.status(user,'kick','error',e.message==='kick_app_missing'?'ربط كيك ينتظر إعداد مالك الموقع؛ لا يحتاج الزائر حسابًا':e.message==='no_channel'?'لم تُوجد القناة؛ تحقق من اسم المستخدم':'تعذّر استقبال كيك؛ تحقق من إعداد التطبيق وWebhook')}
}
