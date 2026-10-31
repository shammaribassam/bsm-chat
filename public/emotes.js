export const emoteImageHosts=['static-cdn.jtvnw.net','files.kick.com','tiktokcdn.com','tiktokcdn-us.com','tiktokcdn-eu.com','byteimg.com','ibyteimg.com','ibytedtos.com'];
export function safeEmoteURL(value){
 if(typeof value!=='string'||value.length>4096)return '';
 try{const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.port)return '';if(!emoteImageHosts.some(h=>u.hostname===h||(!['static-cdn.jtvnw.net','files.kick.com'].includes(h)&&u.hostname.endsWith('.'+h))))return '';return u.href}catch{return ''}
}
const textPart=text=>({type:'text',text});
const imagePart=(text,url)=>safeEmoteURL(url)?{type:'emote',text,url:safeEmoteURL(url)}:textPart(text);

export function messageSegments(provider,e,text){
 if(provider==='twitch'&&Array.isArray(e.message?.fragments)){
  const fragments=e.message.fragments.slice(0,200);
  if(fragments.map(f=>f.text||'').join('')!==text)return [textPart(text)];
  return fragments.map(f=>f.type==='emote'&&/^[\w-]{1,100}$/.test(f.emote?.id||'')?imagePart(f.text,'https://static-cdn.jtvnw.net/emoticons/v2/'+f.emote.id+'/default/dark/2.0'):textPart(f.text||''));
 }
 if(provider==='kick'){
  const out=[];let end=0;for(const match of text.matchAll(/\[emote:(\d{1,30}):([^\]\r\n]{1,100})\]/g)){
   if(out.length>=199)break;if(match.index>end)out.push(textPart(text.slice(end,match.index)));
   out.push(imagePart(match[2],'https://files.kick.com/emotes/'+match[1]+'/fullsize'));end=match.index+match[0].length;
  }if(end<text.length)out.push(textPart(text.slice(end)));return out;
 }
 if(provider==='tiktok'){
  const raw=e.emoteList||e.emotes||[];if(!Array.isArray(raw))return [textPart(text)];
  const out=[],chars=Array.from(text);let end=0;
  const items=raw.slice(0,100).map(item=>({item,at:item.index??item.placeInComment})).sort((a,b)=>(a.at??1e9)-(b.at??1e9));
  for(const {item,at} of items){
   const emote=item.emote||item,url=item.emoteImageUrl||emote.image?.urlList?.[0]||emote.image?.imageUrl;
   if(!safeEmoteURL(url))continue;
   const index=Number.isInteger(at)&&at>=end&&at<=chars.length?at:chars.length;
   if(index>end)out.push(textPart(chars.slice(end,index).join('')));
   const tail=chars.slice(index).join(''),token=tail.match(/^(\[[^\]\r\n]{1,100}\]|\uFFFC)/)?.[0]||'';
   out.push(imagePart(token||'إيموت',url));end=index+Array.from(token).length;
  }
  if(end<chars.length)out.push(textPart(chars.slice(end).join('')));
  return out.length?out:[textPart(text)];
 }
 return [textPart(text)];
}

export function appendMessageContent(element,message){
 const parts=Array.isArray(message.segments)&&message.segments.length?message.segments.slice(0,200):[textPart(message.text||'')];
 for(const part of parts){
  const text=typeof part.text==='string'?part.text.slice(0,2000):'';
  const url=part.type==='emote'?safeEmoteURL(part.url):'';
  if(!url){element.append(document.createTextNode(text));continue}
  const img=document.createElement('img');img.className='chat-emote';img.src=url;img.alt=text;img.title=text;img.referrerPolicy='no-referrer';img.decoding='async';
  img.addEventListener('error',()=>img.replaceWith(document.createTextNode(text)),{once:true});element.append(img);
 }
}
