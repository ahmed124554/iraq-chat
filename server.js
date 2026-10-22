'use strict';
// Iraq Chat server: zero dependencies, needs only Node.js 18+.
const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000,DATA=process.env.DATA_FILE||path.join(__dirname,'data.json');
const ROLES=['bronze','gold','diamond','premium','superpremium','admin','superadmin','owner'];
const lv=r=>ROLES.indexOf(r),DEFP={img:1,aud:2,font:3,hide:5,mod:5},GEN=['ذكر','أنثى','آخر'];
let DB={members:{},rooms:{},flags:{},settings:{},msgs:[]};
try{DB={...DB,...JSON.parse(fs.readFileSync(DATA,'utf8'))}}catch(e){}
let timer=null;
const save=()=>{clearTimeout(timer);timer=setTimeout(()=>{try{fs.writeFileSync(DATA+'.tmp',JSON.stringify(DB));fs.renameSync(DATA+'.tmp',DATA)}catch(e){console.error('save failed',e.message)}},1000)};
const hash=(p,salt=crypto.randomBytes(8).toString('hex'))=>salt+'$'+crypto.scryptSync(p,salt,32).toString('hex');
const verify=(p,h)=>{const[s,x]=(h||'').split('$');if(!s||!x)return false;const a=Buffer.from(hash(p,s).split('$')[1],'hex'),b=Buffer.from(x,'hex');return a.length===b.length&&crypto.timingSafeEqual(a,b)};
if(process.env.OWNER_NAME&&process.env.OWNER_PASS){const n=process.env.OWNER_NAME;DB.members[n]={age:30,gender:'ذكر',font:'',...(DB.members[n]||{}),name:n,role:'owner',ph:hash(process.env.OWNER_PASS)};save()}
if(!Object.keys(DB.rooms).length){['غرفة بغداد','غرفة البصرة','غرفة أربيل'].forEach((n,i)=>DB.rooms['r'+i]={name:n});save()}
const presence={},sessions=new Map(),clients=new Set();
const cfg=()=>{const m=DB.settings.main||{};return{maxRoom:m.maxRoom||50,allowGuests:m.allowGuests!==false,allowReg:m.allowReg!==false,badWords:m.badWords||'',perms:{...DEFP,...(m.perms||{})}}};
const roleOf=u=>u.guest?'bronze':((DB.members[u.name]||{}).role||'bronze');
const pubM=m=>{const{ph,...r}=m;return r};
const arr=o=>Object.entries(o).map(([id,v])=>({...v,id}));
const canSee=(m,name)=>!m.room.startsWith('pm:')||m.room.slice(3).split('|').includes(name);
function send(c,ev,d){c.res.write('event: '+ev+'\ndata: '+JSON.stringify(d)+'\n\n')}
function emit(coll,id,v,filter){const ev=v===null?'del':'set';for(const c of clients)if(!filter||filter(c))send(c,ev,{c:coll,id,v})}
function snapshot(name){return{members:Object.entries(DB.members).map(([id,v])=>({...pubM(v),id})),rooms:arr(DB.rooms),flags:arr(DB.flags),settings:arr(DB.settings),presence:arr(presence),msgs:DB.msgs.filter(m=>canSee(m,name)).slice(-300)}}
const hits={};
function limited(ip){const n=Date.now(),a=(hits[ip]=(hits[ip]||[]).filter(t=>n-t<60000));a.push(n);return a.length>15}
function body(req){return new Promise((res,rej)=>{let s='';req.on('data',d=>{s+=d;if(s.length>1.5e6){rej(new Error('big'));req.destroy()}});req.on('end',()=>{try{res(s?JSON.parse(s):{})}catch(e){rej(e)}})})}
const out=(res,code,o)=>{res.writeHead(code,{'Content-Type':'application/json'});res.end(JSON.stringify(o))};
const fail=(res,code,error)=>out(res,code,{error});
const profile=u=>{const m=u.guest?u:DB.members[u.name]||u;return{name:u.name,age:m.age,gender:m.gender,role:roleOf(u),font:u.guest?'':(DB.members[u.name]||{}).font||'',guest:!!u.guest}};
function nameTaken(n){const l=n.toLowerCase();return Object.keys(DB.members).some(k=>k.toLowerCase()===l)||[...sessions.values()].some(s=>s.name.toLowerCase()===l)}
function newSession(u){const t=crypto.randomBytes(24).toString('hex');sessions.set(t,{...u,ts:Date.now()});return t}
function dropSessions(name){for(const[t,s]of sessions)if(s.name===name)sessions.delete(t);for(const c of[...clients])if(c.name===name){send(c,'kicked',{});c.res.end();clients.delete(c)}clearPresence(name)}
function clearPresence(name){if(presence[name]){delete presence[name];emit('presence',name,null)}}
const NAME=/^[\u0600-\u06FFa-zA-Z0-9 ]{2,20}$/;
async function auth(p,b,req,res){
 if(limited(req.socket.remoteAddress))return fail(res,429,'محاولات كثيرة، انتظر دقيقة');
 const name=String(b.name||'').trim(),c=cfg();
 if(!NAME.test(name))return fail(res,400,'الاسم: حروف عربية أو إنجليزية (2-20 حرفًا)');
 if(DB.flags[name]&&DB.flags[name].banned)return fail(res,403,'هذا الحساب محظور');
 if(p==='login'){const m=DB.members[name];if(!m||!verify(String(b.pass||''),m.ph))return fail(res,401,'الاسم أو كلمة المرور غير صحيحة');const u={name};return out(res,200,{token:newSession(u),me:profile(u)})}
 const age=+b.age,gender=GEN.includes(b.gender)?b.gender:'آخر';
 if(!(age>=1&&age<=99))return fail(res,400,'العمر يجب أن يكون بين 1 و 99');
 if(nameTaken(name))return fail(res,409,'هذا الاسم مستخدم');
 if(p==='guest'){if(!c.allowGuests)return fail(res,403,'دخول الزوار مغلق حاليًا');const u={name,age,gender,guest:true};return out(res,200,{token:newSession(u),me:profile(u)})}
 if(!c.allowReg)return fail(res,403,'التسجيل الجديد مغلق حاليًا');
 const pass=String(b.pass||'');if(pass.length<4||pass.length>100)return fail(res,400,'كلمة المرور 4 أحرف على الأقل');
 const hasOwner=Object.values(DB.members).some(m=>m.role==='owner');
 DB.members[name]={name,age,gender,role:hasOwner?'bronze':'owner',font:'',ph:hash(pass)};save();
 emit('members',name,{...pubM(DB.members[name])});
 const u={name};out(res,200,{token:newSession(u),me:profile(u)});
}
function filt(t){String(cfg().badWords).split(/[,،]/).map(w=>w.trim()).filter(Boolean).forEach(w=>{t=t.split(w).join('***')});return t}
function doc(u,c,id,v,res){
 const role=roleOf(u),r=lv(role),k=cfg(),owner=role==='owner';
 if(typeof id!=='string'||!/^[\w\u0600-\u06FF .-]{1,64}$/.test(id)||!v||typeof v!=='object')return fail(res,400,'طلب غير صالح');
 const ok=()=>out(res,200,{ok:true});
 if(c==='msgs'){
  const f=DB.flags[u.name]||{};if(f.muted)return fail(res,403,'أنت مكتوم من قبل الإدارة');
  const kind=['t','img','aud'].includes(v.kind)?v.kind:'t',m={room:String(v.room||''),from:u.name,r:role,ts:Date.now(),kind};
  if(m.room.startsWith('pm:')){if(!m.room.slice(3).split('|').includes(u.name))return fail(res,403,'غير مسموح')}else if(!DB.rooms[m.room])return fail(res,400,'الغرفة غير موجودة');
  if(kind==='t'){m.text=filt(String(v.text||'').slice(0,500));if(!m.text.trim())return fail(res,400,'رسالة فارغة')}
  else{const need=kind==='img'?k.perms.img:k.perms.aud;if(r<need)return fail(res,403,'عضويتك لا تسمح بهذه الميزة');
   const d=String(v.data||'');if(d.length>300000||!d.startsWith(kind==='img'?'data:image/':'data:audio/'))return fail(res,400,'الملف كبير أو غير صالح');m.data=d}
  if(r>=k.perms.font&&typeof v.font==='string'&&v.font.length<60)m.font=v.font;
  const mid=Date.now().toString(36)+crypto.randomBytes(3).toString('hex');DB.msgs.push({...m,id:mid});if(DB.msgs.length>2000)DB.msgs.splice(0,DB.msgs.length-2000);save();
  emit('msgs',mid,m,cl=>canSee(m,cl.name));return ok()}
 if(c==='presence'){
  if(id!==u.name)return fail(res,403,'غير مسموح');
  const room=String(v.room||'');if(room&&!DB.rooms[room])return fail(res,400,'الغرفة غير موجودة');
  const n=Object.entries(presence).filter(([nm,p])=>nm!==u.name&&p.room===room&&Date.now()-p.ts<60000).length;
  if(room&&n>=k.maxRoom&&!owner)return fail(res,403,'الغرفة ممتلئة ('+k.maxRoom+' عضوًا)');
  const p=profile(u),d={room,ts:Date.now(),invisible:!!v.invisible&&r>=k.perms.hide,role,gender:p.gender,age:p.age};
  presence[u.name]=d;emit('presence',u.name,d);return ok()}
 if(c==='rooms'){if(!owner||typeof v.name!=='string'||!v.name.trim())return fail(res,403,'للمالك فقط');DB.rooms[id]={name:v.name.trim().slice(0,40)};save();emit('rooms',id,DB.rooms[id]);return ok()}
 if(c==='settings'){if(!owner||!['main','bgRoom','bgPm'].includes(id)||JSON.stringify(v).length>300000)return fail(res,403,'للمالك فقط');const{id:_,...x}=v;DB.settings[id]=x;save();emit('settings',id,x);return ok()}
 if(c==='flags'){
  if(r<k.perms.mod)return fail(res,403,'ليست لديك صلاحية');
  const tm=DB.members[id];if(tm&&tm.role==='owner')return fail(res,403,'لا يمكن التعديل على المالك');
  const old=DB.flags[id]||{},n={muted:!!v.muted,alias:String(v.alias||'').slice(0,20),banned:owner?!!v.banned:!!old.banned};
  if(v.kick&&v.kick!==old.kick)n.kick=Date.now();else if(old.kick)n.kick=old.kick;
  DB.flags[id]=n;save();emit('flags',id,n);if(n.kick!==old.kick&&n.kick)dropSessions(id);return ok()}
 if(c==='members'){
  const m=DB.members[id];if(!m)return fail(res,404,'العضو غير موجود');
  if(owner&&m.role!=='owner'){const role2=ROLES.includes(v.role)&&v.role!=='owner'?v.role:m.role;DB.members[id]={...m,role:role2,font:typeof v.font==='string'?v.font.slice(0,60):m.font}}
  else if(id===u.name&&r>=k.perms.font&&typeof v.font==='string')DB.members[id]={...m,font:v.font.slice(0,60)};
  else return fail(res,403,'ليست لديك صلاحية');
  save();emit('members',id,pubM(DB.members[id]));return ok()}
 return fail(res,400,'مجموعة غير معروفة');
}
function del(u,c,id,res){
 const owner=roleOf(u)==='owner',ok=()=>out(res,200,{ok:true});
 if(c==='presence'&&id===u.name){clearPresence(id);return ok()}
 if(!owner)return fail(res,403,'للمالك فقط');
 if(c==='msgs'){DB.msgs=DB.msgs.filter(m=>m.id!==id);save();emit('msgs',id,null);return ok()}
 if(c==='rooms'){delete DB.rooms[id];save();emit('rooms',id,null);return ok()}
 if(c==='members'){const m=DB.members[id];if(!m||m.role==='owner')return fail(res,403,'غير مسموح');delete DB.members[id];save();emit('members',id,null);dropSessions(id);return ok()}
 return fail(res,400,'غير مدعوم');
}
const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://x');
 try{
  if(req.method==='GET'&&(url.pathname==='/'||url.pathname==='/index.html')){res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','X-Content-Type-Options':'nosniff'});return res.end(fs.readFileSync([path.join(__dirname,'public','index.html'),path.join(__dirname,'index.html')].find(f=>fs.existsSync(f))))}
  if(req.method==='GET'&&url.pathname==='/health')return out(res,200,{ok:true});
  if(req.method==='GET'&&url.pathname==='/events'){
   const u=sessions.get(url.searchParams.get('token')||'');if(!u){res.writeHead(401);return res.end()}
   res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-cache','Connection':'keep-alive','X-Accel-Buffering':'no'});
   const c={res,name:u.name};clients.add(c);u.ts=Date.now();send(c,'init',snapshot(u.name));
   req.on('close',()=>{clients.delete(c);if(![...clients].some(x=>x.name===u.name))setTimeout(()=>{if(![...clients].some(x=>x.name===u.name))clearPresence(u.name)},8000)});return}
  if(req.method==='POST'&&url.pathname.startsWith('/api/')){
   const p=url.pathname.slice(5),b=await body(req);
   if(['login','register','guest'].includes(p))return auth(p,b,req,res);
   const tok=req.headers['x-token']||'',u=sessions.get(tok);if(!u)return fail(res,401,'انتهت الجلسة، سجّل الدخول من جديد');
   u.ts=Date.now();
   if(p==='me')return out(res,200,{me:profile(u)});
   if(p==='logout'){sessions.delete(tok);clearPresence(u.name);return out(res,200,{ok:true})}
   if(p==='doc')return doc(u,b.c,b.id,b.v,res);
   if(p==='del')return del(u,b.c,b.id,res);
   return fail(res,404,'غير موجود')}
  res.writeHead(404);res.end('Not found');
 }catch(e){try{fail(res,400,'طلب غير صالح')}catch(_){}}
});
setInterval(()=>{for(const c of clients)c.res.write(': ping\n\n');const n=Date.now();
 for(const[nm,p]of Object.entries(presence))if(n-p.ts>90000)clearPresence(nm);
 for(const[t,s]of sessions)if(n-s.ts>7*864e5||(s.guest&&n-s.ts>6*36e5&&![...clients].some(x=>x.name===s.name)))sessions.delete(t)},25000);
server.listen(PORT,()=>console.log('Iraq Chat running on http://localhost:'+PORT));
