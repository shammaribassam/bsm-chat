// The channel always comes from the authenticated owner's connection.
export async function performAction(providers,user,provider,input){
 const row=providers.row(user,provider);
 if(!row)throw Object.assign(Error('اربط حساب المنصة أولًا'),{status:409});
 if(!['twitch','kick'].includes(provider))throw Object.assign(Error('موصل تيك توك الحالي للاستقبال فقط؛ استخدم أدوات تيك توك للإدارة'),{status:422});
 const token=await providers.token(user,provider),channel=row.external_id;
 const headers={Authorization:'Bearer '+token,'Content-Type':'application/json',...(provider==='twitch'?{'Client-Id':providers.env.TWITCH_CLIENT_ID}:{})};
 const {action,message,text,duration,reason}=input;
 let url,method='POST',body;
 if(provider==='twitch'){
  const query=new URLSearchParams({broadcaster_id:channel,moderator_id:channel});
  if(action==='send'){
   url='https://api.twitch.tv/helix/chat/messages';
   body={broadcaster_id:channel,sender_id:channel,message:text,...(message?{reply_parent_message_id:message.id}:{})};
  }else if(action==='delete'){
   query.set('message_id',message.id);url='https://api.twitch.tv/helix/moderation/chat?'+query;method='DELETE';
  }else{
   url='https://api.twitch.tv/helix/moderation/banned?'+query;
   if(action==='unban'){url+='&user_id='+encodeURIComponent(message.userId);method='DELETE'}
   else body={data:{user_id:message.userId,reason,...(action==='timeout'?{duration:duration*60}:{})}};
  }
 }else{
  const broadcaster_user_id=Number(channel);
  if(action==='send'){
   url='https://api.kick.com/public/v1/chat';
   body={broadcaster_user_id,type:'user',content:text,...(message?{reply_to_message_id:message.id}:{})};
  }else if(action==='delete'){url='https://api.kick.com/public/v1/chat/'+encodeURIComponent(message.id);method='DELETE'}
  else{
   url='https://api.kick.com/public/v1/moderation/bans';
   body={broadcaster_user_id,user_id:Number(message.userId)};
   if(action==='unban')method='DELETE';
   else Object.assign(body,{reason,...(action==='timeout'?{duration}:{})});
  }
 }
 const result=await providers.http(url,{method,headers,...(body?{body:JSON.stringify(body)}:{})});
 if(action==='send'){
  const sent=provider==='twitch'?result.data?.[0]:result.data;
  if(sent?.is_sent!==true)throw Object.assign(Error('لم تؤكد المنصة إرسال الرسالة؛ قد تكون محجوزة للمراجعة'),{status:422});
 }
 return {ok:true};
}
