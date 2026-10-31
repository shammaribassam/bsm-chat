import {DatabaseSync} from 'node:sqlite';
import {mkdirSync} from 'node:fs';
import {dirname} from 'node:path';
import crypto from 'node:crypto';
import {promisify} from 'node:util';
const scrypt=promisify(crypto.scrypt);
export const random=()=>crypto.randomBytes(32).toString('base64url');
export const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
export async function passwordHash(value){const salt=random();return salt+':'+(await scrypt(value,salt,64)).toString('hex')}
export async function passwordCheck(value,stored){const [salt,key]=stored.split(':');const actual=await scrypt(value,salt,64);return crypto.timingSafeEqual(actual,Buffer.from(key,'hex'))}
export function cipher(secret){const key=crypto.createHash('sha256').update(secret).digest();return {seal(value){const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',key,iv);const data=Buffer.concat([c.update(JSON.stringify(value)),c.final()]);return Buffer.concat([iv,c.getAuthTag(),data]).toString('base64')},open(value){const b=Buffer.from(value,'base64'),c=crypto.createDecipheriv('aes-256-gcm',key,b.subarray(0,12));c.setAuthTag(b.subarray(12,28));return JSON.parse(Buffer.concat([c.update(b.subarray(28)),c.final()]).toString())}}}
export function database(path){mkdirSync(dirname(path),{recursive:true});const db=new DatabaseSync(path);db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password TEXT NOT NULL,overlay_hash TEXT UNIQUE NOT NULL,overlay_secret TEXT NOT NULL,settings TEXT NOT NULL DEFAULT '{}',created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS oauth(state TEXT PRIMARY KEY,user_id TEXT NOT NULL,provider TEXT NOT NULL,verifier TEXT NOT NULL,session_hash TEXT NOT NULL,expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS connections(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,provider TEXT NOT NULL,external_id TEXT NOT NULL,channel TEXT NOT NULL,secret TEXT NOT NULL,PRIMARY KEY(user_id,provider),UNIQUE(provider,external_id));
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,event_key TEXT NOT NULL,payload TEXT NOT NULL,created INTEGER NOT NULL,UNIQUE(user_id,event_key));
CREATE INDEX IF NOT EXISTS events_user ON events(user_id,seq);
CREATE TABLE IF NOT EXISTS deliveries(id TEXT PRIMARY KEY,created INTEGER NOT NULL);`);return db}
export const defaults={accent:'#b9f76c',fontSize:18,transparent:true,chat:true,subscription:true,gift:true,like:true,follow:true,share:true,cheer:true,raid:true,blockedWords:''};
export function cleanSettings(value){const out={};for(const k of Object.keys(defaults)){if(typeof defaults[k]==='boolean'&&typeof value[k]==='boolean')out[k]=value[k]}if(/^#[0-9a-f]{6}$/i.test(value.accent||''))out.accent=value.accent;if(Number.isInteger(value.fontSize)&&value.fontSize>=12&&value.fontSize<=40)out.fontSize=value.fontSize;if(typeof value.blockedWords==='string')out.blockedWords=value.blockedWords.slice(0,1000);return out}
export function normalize(provider,type,e){let kind='chat',name='',text='',count=1,id=e.message_id||e.id;
if(provider==='twitch'){
name=e.chatter_user_name||e.user_name||e.from_broadcaster_user_name||'مستخدم';
if(type==='channel.chat.message')text=e.message?.text||'';
else if(type==='channel.subscribe'){if(e.is_gift)return null;kind='subscription';text='اشترك بالقناة'}
else if(type==='channel.subscription.message'){kind='subscription';text=`جدّد الاشتراك · ${e.cumulative_months||1} شهر`}
else if(type==='channel.subscription.gift'){kind='gift';name=e.is_anonymous?'فاعل خير':name;count=e.total||1;text=`أهدى ${count} اشتراكًا 🎁`}
else if(type==='channel.follow'){kind='follow';text='تابع القناة'}
else if(type==='channel.cheer'){kind='cheer';text=`أرسل ${e.bits||0} Bits`}
else if(type==='channel.raid'){kind='raid';text=`دخل ريد مع ${e.viewers||0} مشاهد`}
else return null;
}else if(provider==='kick'){
name=e.sender?.username||e.subscriber?.username||e.gifter?.username||e.follower?.username||'فاعل خير';
if(type==='chat.message.sent')text=e.content||'';
else if(type==='channel.subscription.new'){kind='subscription';text='اشترك بالقناة'}
else if(type==='channel.subscription.renewal'){kind='subscription';text=`جدّد الاشتراك · ${e.duration||1} شهر`}
else if(type==='channel.subscription.gifts'){kind='gift';count=e.giftees?.length||1;text=`أهدى ${count} اشتراكًا 🎁`}
else if(type==='channel.followed'){kind='follow';text='تابع القناة'}
else return null;
}else if(provider==='tiktok'){
name=e.user?.nickname||e.user?.uniqueId||e.nickname||e.uniqueId||'مستخدم';id=e.common?.msgId||e.msgId||id;
if(type==='chat')text=e.comment||'';
else if(type==='gift'){const gift=e.gift||e.giftDetails||{};if((e.giftType===1||gift.giftType===1||gift.type===1)&&!e.repeatEnd)return null;kind='gift';count=Number(e.repeatCount)||1;text=`أرسل ${e.giftName||e.extendedGiftInfo?.name||gift.name||'هدية'} × ${count} 🎁`}
else if(type==='like'){kind='like';count=Number(e.likeCount)||1;text=`أرسل ${count} قلبًا ❤️`}
else if(type==='follow'){kind='follow';text='تابع البث'}else if(type==='share'){kind='share';text='شارك البث'}else return null;
}else return null;
return {id:String(id||random()),provider,kind,name:String(name).slice(0,100),text:String(text).slice(0,2000),count,time:Date.now()}}
