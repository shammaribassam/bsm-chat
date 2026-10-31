import {test} from 'node:test';
import assert from 'node:assert/strict';
import {normalize} from '../core.js';
import {safeEmoteURL,appendMessageContent} from '../public/emotes.js';

test('Twitch fragments preserve Arabic, text ordering and repeated animated emotes',()=>{
 const e={message_id:'tw',message:{text:'هلا Kappa Kappa!',fragments:[{type:'text',text:'هلا '},{type:'emote',text:'Kappa',emote:{id:'25'}},{type:'text',text:' '},{type:'emote',text:'Kappa',emote:{id:'25'}},{type:'text',text:'!'}]}};
 const m=normalize('twitch','channel.chat.message',e);
 assert.equal(m.segments.map(p=>p.text).join(''),e.message.text);
 assert.equal(m.segments.filter(p=>p.type==='emote').length,2);
 assert(m.segments[1].url.endsWith('/25/default/dark/2.0'));
 assert.equal(normalize('twitch','channel.chat.message',{message:{text:'Kappa',fragments:[{type:'emote',text:'Kappa',emote:{id:'../../evil'}}]}}).segments[0].type,'text');
});

test('Kick emote markup becomes inline images without interpreting arbitrary markup',()=>{
 const m=normalize('kick','chat.message.sent',{content:'مرحبا [emote:37226:KEKW] [emote:37226:KEKW] <script>x</script>'});
 assert.equal(m.segments.filter(p=>p.type==='emote').length,2);
 assert.equal(m.segments[1].text,'KEKW');assert.equal(m.segments[1].url,'https://files.kick.com/emotes/37226/fullsize');
 assert(m.segments.at(-1).text.includes('<script>'));
});

test('TikTok modern comments and standalone emote events preserve image metadata',()=>{
 const url='https://p16-webcast.tiktokcdn.com/test-emote.png';
 const m=normalize('tiktok','chat',{content:'😀 [happy] هلا',emotes:[{index:2,emote:{emoteId:'1',image:{urlList:[url]}}}]});
 assert.equal(m.text,'😀 [happy] هلا');assert.deepEqual(m.segments.map(p=>p.type),['text','emote','text']);assert.equal(m.segments[1].text,'[happy]');
 const standalone=normalize('tiktok','emote',{user:{nickname:'viewer'},emoteList:[{image:{urlList:[url]}}]});
 assert.equal(standalone.kind,'chat');assert.equal(standalone.segments[0].type,'emote');
 assert.equal(normalize('tiktok','chat',{comment:'legacy'}).text,'legacy');
});

test('image origins are restricted and old messages remain text with safe fallback on image errors',()=>{
 for(const url of ['javascript:alert(1)','data:image/svg+xml,x','https://attacker.test/x','https://static-cdn.jtvnw.net.evil.test/x','https://files.kick.com@evil.test/x','http://files.kick.com/x','https://files.kick.com:444/x'])assert.equal(safeEmoteURL(url),'');
 const prior=globalThis.document;const elements=[];
 globalThis.document={createTextNode:text=>({text}),createElement:()=>{const node={addEventListener:(type,fn)=>node.onError=fn,replaceWith:replacement=>node.replacement=replacement};elements.push(node);return node}};
 try{
  const out=[],target={append:node=>out.push(node)};
  appendMessageContent(target,{text:'old <img onerror=x>'});assert.equal(out[0].text,'old <img onerror=x>');
  appendMessageContent(target,{segments:[{type:'emote',text:'Kappa',url:'https://static-cdn.jtvnw.net/emoticons/v2/25/default/dark/2.0'},{type:'emote',text:'blocked',url:'https://evil.test/x'}]});
  assert.equal(elements.length,1);assert.equal(out.at(-1).text,'blocked');elements[0].onError();assert.equal(elements[0].replacement.text,'Kappa');
 }finally{if(prior===undefined)delete globalThis.document;else globalThis.document=prior}
});
