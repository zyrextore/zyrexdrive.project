import express from "express";
import http from "http";
import crypto from "crypto";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { initDatabase, databaseStatus, pingDatabase, saveState } from "./db.js";

const __filename=fileURLToPath(import.meta.url), __dirname=path.dirname(__filename);
const app=express(), server=http.createServer(app);
const VERSION="V115";
const PORT=Number(process.env.PORT||3000);
const ADMIN_USERNAME=process.env.ADMIN_USERNAME||"admin";
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||"CHANGE_THIS_PASSWORD";
const SESSION_SECRET=process.env.SESSION_SECRET||"CHANGE_THIS_RANDOM_SECRET";
app.set("trust proxy",1);
app.disable("x-powered-by");
app.use((req,res,next)=>{
  const rid=crypto.randomUUID();
  req.requestId=rid;
  res.setHeader("X-Request-ID",rid);
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","SAMEORIGIN");
  res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy","camera=(), microphone=(), geolocation=()");
  res.setHeader("X-DNS-Prefetch-Control","off");
  res.setHeader("Cross-Origin-Resource-Policy","same-origin");
  if(process.env.NODE_ENV==="production")res.setHeader("Strict-Transport-Security","max-age=31536000; includeSubDomains");
  next();
});
// V104 — BuatQris payment gateway configuration. Secrets stay server-side.
const BQ_API_URL=String(process.env.BQ_API_URL||"https://api.buatqris.site").replace(/\/$/,"");
const BQ_ACCOUNT_ID=String(process.env.BQ_ACCOUNT_ID||"");
const BQ_SECRET_TOKEN=String(process.env.BQ_SECRET_TOKEN||"");
const BQ_WEBHOOK_SECRET=String(process.env.BQ_WEBHOOK_SECRET||"");
const BQ_QRIS_METHOD=String(process.env.BQ_QRIS_METHOD||"qris_two");
const BQ_FEE_BY=String(process.env.BQ_FEE_BY||"user");
const BQ_MODE=String(process.env.BQ_MODE||"sandbox").toLowerCase()==="real"?"real":"sandbox";
const BQ_ENABLED=Boolean(BQ_ACCOUNT_ID&&BQ_SECRET_TOKEN);

function paymentAudit(action,meta={}){paymentLedger.unshift({id:id("PAY"),action,createdAt:new Date().toISOString(),requestId:meta.requestId||null,...meta});if(paymentLedger.length>5000)paymentLedger.splice(5000);logAction(`payment.${action}`,meta);persist();}
function markPaymentStatus(o,status,source="unknown",extra={}){
  const normalized=String(status||"pending").toLowerCase();
  o.payment=o.payment||{};o.payment.status=normalized;o.payment.lastStatusSource=source;o.payment.checkedAt=new Date().toISOString();
  if(extra.transactionId)o.payment.transactionId=extra.transactionId;
  if(normalized==="success"){
    const wasPaid=["Paid","Verified"].includes(o.paymentStatus);
    o.paymentStatus="Paid";o.paymentVerified=true;o.status=o.status==="Cancelled"?o.status:"Processing";consumeReservation(o.id);o.paidAt=o.paidAt||new Date().toISOString();
    if(!wasPaid){recordAnalytics("payment_success",{orderId:o.id,productId:o.productId,source});notify(o.userId,"Pembayaran berhasil",`Pembayaran untuk ${o.id} diterima. Order sedang diproses.`,"payment",{orderId:o.id});}
  }else if(normalized==="expired"){
    const changed=o.paymentStatus!=="Expired";o.paymentStatus="Expired";if(changed)notify(o.userId,"Pembayaran kedaluwarsa",`QRIS untuk ${o.id} sudah kedaluwarsa.` ,"payment",{orderId:o.id});
    recordAnalytics("payment_expired",{orderId:o.id,productId:o.productId,source});
  }else if(normalized==="failed"){
    const changed=o.paymentStatus!=="Failed";o.paymentStatus="Failed";if(changed)notify(o.userId,"Pembayaran gagal",`Pembayaran ${o.id} gagal. Silakan coba lagi.` ,"payment",{orderId:o.id});
    recordAnalytics("payment_failed",{orderId:o.id,productId:o.productId,source});
  }else o.paymentStatus="Pending";
  paymentAudit("status",{orderId:o.id,transactionId:o.payment.transactionId||o.transactionId||null,status:normalized,source});
}
function getIdempotency(key,orderId){return paymentIdempotency.find(x=>x.key===key&&x.orderId===orderId&&x.expiresAt>Date.now())}
function saveIdempotency(key,orderId,payment){const row={key,orderId,payment,createdAt:new Date().toISOString(),expiresAt:Date.now()+24*60*60*1000};paymentIdempotency.push(row);if(paymentIdempotency.length>5000)paymentIdempotency.splice(0,paymentIdempotency.length-5000);persist();return row}

// Webhook must receive the exact raw request body for HMAC-SHA256 verification.
app.post("/api/payments/buatqris/webhook",express.raw({type:"*/*",limit:"1mb"}),(req,res)=>{
  const raw=Buffer.isBuffer(req.body)?req.body:Buffer.from(req.body||"");
  const supplied=String(req.headers["x-buatqris-signature"]||"");
  if(!BQ_WEBHOOK_SECRET)return res.status(503).json({error:"Webhook belum dikonfigurasi"});
  const expected="sha256="+crypto.createHmac("sha256",BQ_WEBHOOK_SECRET).update(raw).digest("hex");
  if(supplied.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(supplied),Buffer.from(expected)))return res.status(401).json({error:"Invalid webhook signature"});
  let data;try{data=JSON.parse(raw.toString("utf8"))}catch{return res.status(400).json({error:"Invalid JSON"})}
  const event=clean(data?.event,80),tx=clean(data?.transaction_id,120),status=clean(data?.status,40).toLowerCase();
  const eventId=clean(data?.event_id||data?.id,120)||crypto.createHash("sha256").update(raw).digest("hex");
  if(paymentWebhookEvents.some(x=>x.id===eventId))return res.status(200).json({ok:true,duplicate:true});
  paymentWebhookEvents.push({id:eventId,transactionId:tx,event,status,receivedAt:new Date().toISOString()});
  if(paymentWebhookEvents.length>2000)paymentWebhookEvents.splice(0,paymentWebhookEvents.length-2000);
  const o=orders.find(x=>x.payment?.transactionId===tx||x.transactionId===tx);
  if(o){
    o.payment=o.payment||{}; o.payment.lastWebhookAt=new Date().toISOString(); o.payment.gatewayStatus=status||event;
    const effective=status||event.replace(/^payment\./,"");
    markPaymentStatus(o,effective,"webhook",{transactionId:tx,requestId:req.requestId});
    logAction("payment.webhook",{orderId:o.id,transactionId:tx,event,status,requestId:req.requestId});
  }
  res.status(200).json({ok:true});
});

app.use(express.json({limit:"2mb"}));
app.use((req,res,next)=>{if(systemSettings.maintenance&&!req.path.startsWith("/api/admin")&&!req.path.startsWith("/api/health"))return res.status(503).json({error:"ZYREX sedang maintenance",announcement:systemSettings.announcement});next()});
app.use(express.static(path.join(__dirname,"public")));

const DATA_DIR=process.env.DATA_DIR||path.join(__dirname,"data"), DATA_FILE=path.join(DATA_DIR,"zyrex-data.json"), BACKUP_DIR=path.join(DATA_DIR,"backups");
fs.mkdirSync(DATA_DIR,{recursive:true}); fs.mkdirSync(BACKUP_DIR,{recursive:true});
const SCHEMA_VERSION=6;
const SYSTEM_SETTINGS={maintenance:false,announcement:"",allowRegistrations:true};
const defaults={users:[],sessions:[],achievements:[],promos:[{code:"ZYREX10",type:"percent",value:10,active:true,maxUses:100,usedCount:0,perUserLimit:1,minSubtotal:0}],products:[

{id:"P001",name:"Landing Page Pro",category:"Web",price:250000,description:"Landing page modern dan responsive.",featured:true,published:true,stock:99,variants:[{id:"starter",name:"Starter",priceDelta:0,stock:49},{id:"pro",name:"Pro",priceDelta:75000,stock:30}],startAt:null,endAt:null},
{id:"P002",name:"Pterodactyl Panel Setup",category:"Server",price:150000,description:"Setup dan konfigurasi panel server.",featured:false,published:true,stock:99,variants:[],startAt:null,endAt:null},
{id:"P003",name:"WhatsApp Bot Starter",category:"Bot",price:300000,description:"Bot starter untuk automation.",featured:false,published:true,stock:99,variants:[],startAt:null,endAt:null},
{id:"P004",name:"Custom Dashboard UI",category:"Software",price:450000,description:"Dashboard UI premium dan responsive.",featured:true,published:true,stock:99,variants:[],startAt:null,endAt:null},
{id:"P005",name:"API Integration",category:"API",price:350000,description:"Integrasi API untuk menghubungkan layanan digital.",featured:false,published:true,stock:99,variants:[],startAt:null,endAt:null}],orders:[],inquiries:[],scores:[],reviews:[],activityLogs:[],passwordResets:[],notifications:[],analyticsEvents:[],schemaVersion:SCHEMA_VERSION,systemSettings:{...SYSTEM_SETTINGS}};
let saved={};
try{saved=JSON.parse(fs.readFileSync(DATA_FILE,"utf8"))||{}}catch{saved={}}
const products=Array.isArray(saved.products)&&saved.products.length?saved.products:defaults.products;
const orders=Array.isArray(saved.orders)?saved.orders:[];
const inquiries=Array.isArray(saved.inquiries)?saved.inquiries:[];
const scores=Array.isArray(saved.scores)?saved.scores:[];
const reviews=Array.isArray(saved.reviews)?saved.reviews:[];
const users=Array.isArray(saved.users)?saved.users:[];
const connections=Array.isArray(saved.connections)?saved.connections:[];
const challenges=Array.isArray(saved.challenges)?saved.challenges:[];
const achievements=Array.isArray(saved.achievements)?saved.achievements:[];
const sessions=Array.isArray(saved.sessions)?saved.sessions:[];
const promos=Array.isArray(saved.promos)?saved.promos:defaults.promos;
const activityLogs=Array.isArray(saved.activityLogs)?saved.activityLogs:[];
const passwordResets=Array.isArray(saved.passwordResets)?saved.passwordResets:[];
const notifications=Array.isArray(saved.notifications)?saved.notifications:[];
const analyticsEvents=Array.isArray(saved.analyticsEvents)?saved.analyticsEvents:[];
const adminSessions=Array.isArray(saved.adminSessions)?saved.adminSessions:[];
const paymentWebhookEvents=Array.isArray(saved.paymentWebhookEvents)?saved.paymentWebhookEvents:[];
const paymentLedger=Array.isArray(saved.paymentLedger)?saved.paymentLedger:[];
const paymentIdempotency=Array.isArray(saved.paymentIdempotency)?saved.paymentIdempotency:[];
const inventoryMovements=Array.isArray(saved.inventoryMovements)?saved.inventoryMovements:[];
const inventoryReservations=Array.isArray(saved.inventoryReservations)?saved.inventoryReservations:[];
const systemSettings={...SYSTEM_SETTINGS,...(saved.systemSettings||{})};
function snapshot(){return {schemaVersion:SCHEMA_VERSION,products,orders,inquiries,scores,reviews,users,sessions,promos,activityLogs,passwordResets,notifications,analyticsEvents,connections,challenges,adminSessions,paymentWebhookEvents,paymentLedger,paymentIdempotency,inventoryMovements,inventoryReservations,systemSettings}}
function applyState(payload){
  if(!payload||typeof payload!=="object")return;
  const copy=(target,key,fallback=[])=>{if(Array.isArray(payload[key]))target.splice(0,target.length,...payload[key]);else if(target.length===0)target.splice(0,target.length,...fallback)};
  copy(products,"products",defaults.products);copy(orders,"orders");copy(inquiries,"inquiries");copy(scores,"scores");copy(reviews,"reviews");copy(users,"users");copy(sessions,"sessions");copy(promos,"promos",defaults.promos);copy(activityLogs,"activityLogs");copy(passwordResets,"passwordResets");copy(notifications,"notifications");copy(analyticsEvents,"analyticsEvents");copy(adminSessions,"adminSessions");copy(paymentWebhookEvents,"paymentWebhookEvents");copy(connections,"connections");copy(challenges,"challenges");copy(paymentLedger,"paymentLedger");copy(paymentIdempotency,"paymentIdempotency");copy(inventoryMovements,"inventoryMovements");copy(inventoryReservations,"inventoryReservations");
  if(payload.systemSettings&&typeof payload.systemSettings==="object")Object.assign(systemSettings,payload.systemSettings);
}
function persist(){const data=snapshot(),tmp=DATA_FILE+".tmp";fs.writeFileSync(tmp,JSON.stringify(data,null,2));fs.renameSync(tmp,DATA_FILE);void saveState(data)}
products.forEach(p=>{if(typeof p.stock!=="number")p.stock=99;if(!Array.isArray(p.variants))p.variants=[];if(p.published===undefined)p.published=true;if(p.startAt===undefined)p.startAt=null;if(p.endAt===undefined)p.endAt=null;p.variants.forEach(v=>{if(!v.id)v.id=id("VAR");if(typeof v.stock!=="number")v.stock=0;if(typeof v.priceDelta!=="number")v.priceDelta=0})});
promos.forEach(p=>{p.maxUses=Number.isFinite(Number(p.maxUses))?Number(p.maxUses):0;p.usedCount=Number(p.usedCount)||0;p.perUserLimit=Number(p.perUserLimit)||0;p.minSubtotal=Number(p.minSubtotal)||0});
users.forEach(u=>{if(typeof u.bio!=="string")u.bio="ZYREX explorer";if(typeof u.avatar!=="string")u.avatar="";});
// Keep a rolling automatic backup before normal writes.
function makeBackup(){try{if(!fs.existsSync(DATA_FILE))return null;const stamp=new Date().toISOString().replace(/[:.]/g,"-");const target=path.join(BACKUP_DIR,`zyrex-${stamp}.json`);fs.copyFileSync(DATA_FILE,target);const files=fs.readdirSync(BACKUP_DIR).sort().reverse();for(const f of files.slice(10))try{fs.unlinkSync(path.join(BACKUP_DIR,f))}catch{};return target}catch{return null}}
// V114 migration normalizes product/promo/inventory fields; persistence writes schema 6.
persist();
const requestLog=new Map();
const loginFailures=new Map();

function rateLimit(key,limit=12,windowMs=60000){const now=Date.now(),hits=(requestLog.get(key)||[]).filter(t=>now-t<windowMs);if(hits.length>=limit){requestLog.set(key,hits);return false}hits.push(now);requestLog.set(key,hits);return true}
function clean(v,max){return typeof v==="string"?v.trim().slice(0,max):""}
function sign(p){return crypto.createHmac("sha256",SESSION_SECRET).update(p).digest("hex")}
function token(user){const jti=crypto.randomUUID(),exp=Date.now()+28800000,p=`${user}.${Date.now()}.${exp}.${jti}`;adminSessions.push({jti,user,expiresAt:exp,createdAt:new Date().toISOString()});if(adminSessions.length>20)adminSessions.splice(0,adminSessions.length-20);persist();return `${Buffer.from(p).toString("base64url")}.${sign(p)}`}
function verify(req){const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))return false;const [e,s]=h.slice(7).split(".");if(!e||!s)return false;let p;try{p=Buffer.from(e,"base64url").toString()}catch{return false}const x=sign(p);if(s.length!==x.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(x)))return false;const a=p.split("."),jti=a[3];return a.length===4&&a[0]===ADMIN_USERNAME&&Number(a[2])>Date.now()&&adminSessions.some(x=>x.jti===jti&&x.user===ADMIN_USERNAME&&x.expiresAt>Date.now())}
function admin(req,res,next){if(!verify(req))return res.status(401).json({error:"Unauthorized"});next()}
function id(prefix){return `${prefix}-${Date.now().toString(36).toUpperCase()}-${crypto.randomBytes(2).toString("hex").toUpperCase()}`}
function hashPassword(password,salt=crypto.randomBytes(16).toString("hex")){return `${salt}:${crypto.scryptSync(password,salt,32).toString("hex")}`}
function checkPassword(password,stored){try{const [salt,hash]=String(stored).split(":");const got=crypto.scryptSync(password,salt,32).toString("hex");return hash&&got.length===hash.length&&crypto.timingSafeEqual(Buffer.from(got),Buffer.from(hash))}catch{return false}}
function userFromReq(req){const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))return null;const sess=sessions.find(x=>x.token===h.slice(7)&&x.expiresAt>Date.now());return sess?users.find(u=>u.id===sess.userId)||null:null}
function user(req,res,next){const u=userFromReq(req);if(!u)return res.status(401).json({error:"Login diperlukan"});req.user=u;next()}
function publicUser(u){return {id:u.id,name:u.name,email:u.email,createdAt:u.createdAt,bio:u.bio||"ZYREX explorer",avatar:u.avatar||""}}
function publicProfile(u){
  const mine=scores.filter(s=>s.userId===u.id);
  const gameStats={}; VALID_GAMES.forEach(g=>{const rows=mine.filter(s=>s.game===g);gameStats[g]={games:rows.length,best:rows.reduce((m,x)=>Math.max(m,x.score),0),total:rows.reduce((m,x)=>m+x.score,0)}});
  const xp=achievements.filter(a=>a.userId===u.id).reduce((n,a)=>n+(a.xp||0),0);
  return {id:u.id,name:u.name,bio:u.bio||"ZYREX explorer",avatar:u.avatar||"",createdAt:u.createdAt,level:Math.floor(xp/100)+1,xp,achievements:achievements.filter(a=>a.userId===u.id).map(a=>({id:a.achievementId,name:a.name,xp:a.xp,game:a.game,score:a.score,createdAt:a.createdAt})),gameStats,connections:connections.filter(c=>c.status==="accepted"&&(c.a===u.id||c.b===u.id)).length};
}
function logAction(action,meta={}){activityLogs.unshift({id:id("LOG"),action,meta,createdAt:new Date().toISOString()});if(activityLogs.length>500)activityLogs.length=500;persist()}
function notify(userId,title,message,type="info",meta={}){if(!userId)return;notifications.unshift({id:id("NTF"),userId,title:clean(title,100),message:clean(message,300),type:clean(type,20)||"info",read:false,meta,createdAt:new Date().toISOString()});if(notifications.length>1000)notifications.length=1000;persist()}
function recordAnalytics(event,meta={}){
  const allowed=["page_view","store_view","product_view","checkout_start","order_created","payment_success","payment_failed","payment_expired"];
  if(!allowed.includes(event))return;
  analyticsEvents.push({id:id("EVT"),event,meta:{productId:clean(meta.productId,30),orderId:clean(meta.orderId,40),source:clean(meta.source,30),userId:clean(meta.userId,60)},createdAt:new Date().toISOString()});
  if(analyticsEvents.length>10000)analyticsEvents.splice(0,analyticsEvents.length-10000);
  persist();
}


app.get("/api/health",(req,res)=>res.json({ok:true,service:"ZYREX",version:VERSION,uptime:Math.round(process.uptime()),dataFile:fs.existsSync(DATA_FILE),timestamp:new Date().toISOString()}));
app.get("/api/health/database",async(req,res)=>{const ok=await pingDatabase();res.status(databaseStatus().configured&&!ok?503:200).json({version:VERSION,database:{...databaseStatus(),reachable:ok}})});
app.post("/api/analytics/event",(req,res)=>{
 const ip=req.ip||"unknown";if(!rateLimit("analytics:"+ip,60,60000))return res.status(429).json({error:"Analytics rate limited"});
 const event=clean(req.body?.event,40),productId=clean(req.body?.productId,30),source=clean(req.body?.source,30)||"web";
 recordAnalytics(event,{productId,source});res.status(202).json({ok:true});
});
app.post("/api/auth/register",(req,res)=>{if(!systemSettings.allowRegistrations)return res.status(403).json({error:"Registrasi sedang dinonaktifkan"});const name=clean(req.body?.name,60),email=clean(req.body?.email,120).toLowerCase(),password=String(req.body?.password||"");if(!name||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<8)return res.status(400).json({error:"Nama, email valid, dan password minimal 8 karakter wajib diisi"});if(users.some(u=>u.email===email))return res.status(409).json({error:"Email sudah terdaftar"});const u={id:id("USR"),name,email,passwordHash:hashPassword(password),createdAt:new Date().toISOString()};users.push(u);const token=crypto.randomBytes(32).toString("hex");sessions.push({token,userId:u.id,createdAt:new Date().toISOString(),expiresAt:Date.now()+2592000000});persist();res.status(201).json({token,user:publicUser(u)})});
app.post("/api/auth/login",(req,res)=>{const ip=req.ip||"unknown";if(!rateLimit("login:"+ip,8,300000))return res.status(429).json({error:"Terlalu banyak percobaan login. Coba lagi nanti."});const email=clean(req.body?.email,120).toLowerCase(),password=String(req.body?.password||"");const u=users.find(x=>x.email===email);if(!u||!checkPassword(password,u.passwordHash))return res.status(401).json({error:"Email atau password salah"});const token=crypto.randomBytes(32).toString("hex");sessions.push({token,userId:u.id,createdAt:new Date().toISOString(),expiresAt:Date.now()+2592000000});persist();res.json({token,user:publicUser(u)})});
app.post("/api/auth/logout",user,(req,res)=>{const h=req.headers.authorization||"";const i=sessions.findIndex(x=>x.token===h.slice(7));if(i>=0)sessions.splice(i,1);persist();res.json({ok:true})});
app.get("/api/auth/me",user,(req,res)=>res.json(publicUser(req.user)));
app.get("/api/auth/sessions",user,(req,res)=>{
  const current=(req.headers.authorization||"").slice(7);
  res.json(sessions.filter(s=>s.userId===req.user.id&&s.expiresAt>Date.now()).map(s=>({id:crypto.createHash("sha256").update(s.token).digest("hex").slice(0,12),current:s.token===current,createdAt:s.createdAt||null,expiresAt:s.expiresAt})));
});
app.delete("/api/auth/sessions",user,(req,res)=>{
  const current=(req.headers.authorization||"").slice(7);
  const keep=sessions.find(s=>s.token===current&&s.userId===req.user.id);
  sessions.splice(0,sessions.length,...sessions.filter(s=>s.userId!==req.user.id));
  if(keep)sessions.push(keep);
  persist(); res.json({ok:true});
});
app.get("/api/notifications",user,(req,res)=>{const list=notifications.filter(n=>n.userId===req.user.id).sort((a,b)=>Date.parse(b.createdAt)-Date.parse(a.createdAt)).slice(0,50);res.json({items:list,unread:list.filter(n=>!n.read).length})});
app.patch("/api/notifications/:id/read",user,(req,res)=>{const n=notifications.find(x=>x.id===req.params.id&&x.userId===req.user.id);if(!n)return res.status(404).json({error:"Notifikasi tidak ditemukan"});n.read=true;persist();res.json(n)});
app.post("/api/notifications/read-all",user,(req,res)=>{notifications.filter(n=>n.userId===req.user.id&&!n.read).forEach(n=>n.read=true);persist();res.json({ok:true})});
app.patch("/api/auth/me",user,(req,res)=>{const name=clean(req.body?.name,60);if(!name)return res.status(400).json({error:"Nama wajib diisi"});req.user.name=name;persist();res.json(publicUser(req.user))});
app.get("/api/community/users",(req,res)=>{const q=clean(req.query?.q,60).toLowerCase();if(!q)return res.json([]);res.json(users.filter(u=>(u.name+" "+u.email).toLowerCase().includes(q)).slice(0,20).map(u=>({id:u.id,name:u.name,bio:u.bio||"ZYREX explorer",avatar:u.avatar||""})))});
app.get("/api/community/profile/:id",(req,res)=>{const u=users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:"Player tidak ditemukan"});res.json(publicProfile(u))});
app.patch("/api/community/profile",user,(req,res)=>{if(req.body.name!==undefined)req.user.name=clean(req.body.name,60)||req.user.name;if(req.body.bio!==undefined)req.user.bio=clean(req.body.bio,120);if(req.body.avatar!==undefined)req.user.avatar=clean(req.body.avatar,500);persist();res.json(publicProfile(req.user))});
app.get("/api/community/connections",user,(req,res)=>{const list=connections.filter(c=>c.a===req.user.id||c.b===req.user.id).map(c=>{const other=users.find(u=>u.id===(c.a===req.user.id?c.b:c.a));return {...c,other:other?{id:other.id,name:other.name,bio:other.bio||"ZYREX explorer"}:null}});res.json(list)});
app.post("/api/community/connections",user,(req,res)=>{const target=users.find(u=>u.id===clean(req.body?.userId,60));if(!target||target.id===req.user.id)return res.status(400).json({error:"Player tidak valid"});let c=connections.find(x=>(x.a===req.user.id&&x.b===target.id)||(x.a===target.id&&x.b===req.user.id));if(c)return res.json(c);c={id:id("CON"),a:req.user.id,b:target.id,status:"accepted",createdAt:new Date().toISOString()};connections.push(c);notify(target.id,"New connection",`${req.user.name} terhubung dengan kamu.` ,"social",{userId:req.user.id});logAction("connection.created",{from:req.user.id,to:target.id});persist();res.status(201).json(c)});
app.delete("/api/community/connections/:userId",user,(req,res)=>{const i=connections.findIndex(c=>(c.a===req.user.id&&c.b===req.params.userId)||(c.b===req.user.id&&c.a===req.params.userId));if(i<0)return res.status(404).json({error:"Connection tidak ditemukan"});connections.splice(i,1);persist();res.json({ok:true})});
app.get("/api/community/challenges",user,(req,res)=>res.json(challenges.filter(c=>c.from===req.user.id||c.to===req.user.id).slice(0,50)));
app.post("/api/community/challenges",user,(req,res)=>{const target=users.find(u=>u.id===clean(req.body?.to,60)),game=clean(req.body?.game,30),score=Math.max(1,Math.min(999999,Number(req.body?.targetScore)||0));if(!target||target.id===req.user.id||!VALID_GAMES.includes(game)||!score)return res.status(400).json({error:"Challenge tidak valid"});const c={id:id("CHL"),from:req.user.id,to:target.id,game,targetScore:score,status:"open",createdAt:new Date().toISOString()};challenges.unshift(c);notify(target.id,"New challenge",`${req.user.name} menantang kamu di ${game}. Target ${score}.`,"challenge",{challengeId:c.id});persist();res.status(201).json(c)});
app.patch("/api/community/challenges/:id",user,(req,res)=>{const c=challenges.find(x=>x.id===req.params.id&&x.to===req.user.id);if(!c)return res.status(404).json({error:"Challenge tidak ditemukan"});const status=["accepted","declined"].includes(req.body?.status)?req.body.status:"open";c.status=status;if(status==="accepted")notify(c.from,"Challenge accepted",`${req.user.name} menerima challenge kamu.` ,"challenge",{challengeId:c.id});persist();res.json(c)});
app.post("/api/auth/forgot-password",(req,res)=>{const email=clean(req.body?.email,120).toLowerCase();const u=users.find(x=>x.email===email);let raw="";if(u){raw=crypto.randomBytes(24).toString("hex");passwordResets.push({token:crypto.createHash("sha256").update(raw).digest("hex"),userId:u.id,expiresAt:Date.now()+900000});persist();}const out={ok:true,message:"Jika email terdaftar, instruksi reset akan dikirim."};if(raw&&process.env.RESET_DEV_MODE==="true")out.resetToken=raw;res.json(out)});
app.post("/api/auth/reset-password",(req,res)=>{const raw=clean(req.body?.token,100),next=String(req.body?.newPassword||"");if(!raw||next.length<8)return res.status(400).json({error:"Token dan password baru minimal 8 karakter wajib diisi"});const h=crypto.createHash("sha256").update(raw).digest("hex"),r=passwordResets.find(x=>x.token===h&&x.expiresAt>Date.now());if(!r)return res.status(400).json({error:"Reset token tidak valid atau sudah kedaluwarsa"});const u=users.find(x=>x.id===r.userId);if(!u)return res.status(400).json({error:"User tidak ditemukan"});u.passwordHash=hashPassword(next);sessions.splice(0,sessions.length,...sessions.filter(x=>x.userId!==u.id));passwordResets.splice(passwordResets.indexOf(r),1);persist();res.json({ok:true})});
app.post("/api/auth/change-password",user,(req,res)=>{const old=String(req.body?.oldPassword||""),next=String(req.body?.newPassword||"");if(!checkPassword(old,req.user.passwordHash)||next.length<8)return res.status(400).json({error:"Password lama salah atau password baru terlalu pendek"});req.user.passwordHash=hashPassword(next);sessions.splice(0,sessions.length,...sessions.filter(x=>x.userId!==req.user.id));persist();res.json({ok:true})});

function productVisible(p){const now=Date.now();if(p.published===false)return false;if(p.startAt&&Date.parse(p.startAt)>now)return false;if(p.endAt&&Date.parse(p.endAt)<=now)return false;return true}
function variantFor(product,variantId){return Array.isArray(product?.variants)&&product.variants.length?(product.variants.find(v=>v.id===variantId)||null):null}
function availableStock(product,variant){return variant?Number(variant.stock||0):Number(product.stock||0)}
function inventoryMove(productId,variantId,delta,reason,meta={}){inventoryMovements.unshift({id:id("INV"),productId,variantId:variantId||null,delta,reason,createdAt:new Date().toISOString(),meta});if(inventoryMovements.length>3000)inventoryMovements.length=3000}
function reserveInventory(orderId,product,variant,qty=1){const n=Math.max(1,Math.floor(qty));if(availableStock(product,variant)<n)return false;if(variant)variant.stock-=n;else product.stock-=n;const r={id:id("RES"),orderId,productId:product.id,variantId:variant?.id||null,qty:n,status:"reserved",createdAt:new Date().toISOString(),expiresAt:Date.now()+20*60*1000};inventoryReservations.unshift(r);inventoryMove(product.id,variant?.id,-n,"reserve",{orderId});return r}
function releaseReservation(orderId,reason="release"){const r=inventoryReservations.find(x=>x.orderId===orderId&&x.status==="reserved");if(!r)return false;const p=products.find(x=>x.id===r.productId),v=variantFor(p,r.variantId);if(v)v.stock+=r.qty;else if(p)p.stock=(p.stock||0)+r.qty;r.status="released";r.releasedAt=new Date().toISOString();r.releaseReason=reason;inventoryMove(r.productId,r.variantId,r.qty,reason,{orderId});return true}
function consumeReservation(orderId){const r=inventoryReservations.find(x=>x.orderId===orderId&&x.status==="reserved");if(r){r.status="consumed";r.consumedAt=new Date().toISOString();return true}return false}
function promoUsage(promo,userId){return orders.filter(o=>o.promoCode===promo.code&&(!userId||o.userId===userId)&&o.status!=="Cancelled").length}
function promoValid(promo,subtotal,userId){if(!promo||!promo.active)return false;const now=Date.now();if(promo.startsAt&&Date.parse(promo.startsAt)>now)return false;if(promo.endsAt&&Date.parse(promo.endsAt)<=now)return false;if(Number(promo.maxUses)>0&&Number(promo.usedCount||0)>=Number(promo.maxUses))return false;if(Number(promo.minSubtotal||0)>subtotal)return false;if(userId&&Number(promo.perUserLimit||0)>0&&promoUsage(promo,userId)>=Number(promo.perUserLimit))return false;return true}
function promoDiscount(promo,subtotal){if(!promoValid(promo,subtotal,null))return 0;return promo.type==="fixed"?Math.min(subtotal,Math.max(0,Number(promo.value)||0)):Math.min(subtotal,Math.round(subtotal*Math.min(100,Math.max(0,Number(promo.value)||0))/100))}

app.post("/api/promo/validate",(req,res)=>{const code=clean(req.body?.code,30).toUpperCase(),subtotal=Math.max(0,Number(req.body?.subtotal)||0),u=userFromReq(req),promo=promos.find(x=>x.code===code);if(!promo||!promoValid(promo,subtotal,u?.id))return res.status(404).json({error:"Promo tidak tersedia atau batas penggunaannya tercapai"});res.json({code:promo.code,type:promo.type,value:promo.value,discount:promoDiscount(promo,subtotal),remainingUses:Number(promo.maxUses)>0?Math.max(0,Number(promo.maxUses)-(Number(promo.usedCount)||0)):null})});
app.get("/api/products",(req,res)=>{const now=Date.now(),featured=req.query.featured==="true";res.json(products.filter(productVisible).filter(p=>!featured||p.featured).map(p=>({...p,variants:(p.variants||[]).map(v=>({...v,price:Math.max(0,p.price+Number(v.priceDelta||0))}))}))) });

app.post("/api/orders",(req,res)=>{
 const ip=req.ip||"unknown";if(!rateLimit("order:"+ip,8))return res.status(429).json({error:"Terlalu banyak order. Coba lagi sebentar."});
 const product=products.find(p=>p.id===req.body?.productId),name=clean(req.body?.customerName,100),contact=clean(req.body?.customerContact,120),proof=clean(req.body?.paymentProof,1800000),promoCode=clean(req.body?.promoCode,30).toUpperCase(),u=userFromReq(req),variant=product?variantFor(product,clean(req.body?.variantId,60)):null,qty=Math.max(1,Math.min(20,Math.floor(Number(req.body?.qty)||1))),promo=promos.find(x=>x.code===promoCode);
 if(!product||!productVisible(product))return res.status(400).json({error:"Product tidak tersedia"});if(product.variants?.length&&!variant)return res.status(400).json({error:"Pilih varian produk"});if(!name||!contact)return res.status(400).json({error:"Nama dan kontak wajib diisi"});if(!Number.isFinite(qty)||availableStock(product,variant)<qty)return res.status(409).json({error:"Stock tidak mencukupi"});
 const unitPrice=Math.max(0,product.price+Number(variant?.priceDelta||0)),subtotal=unitPrice*qty;if(promoCode&&!promoValid(promo,subtotal,u?.id))return res.status(400).json({error:"Promo tidak tersedia atau batas penggunaannya tercapai"});
 const discount=promo?promoDiscount(promo,subtotal):0,finalPrice=Math.max(0,subtotal-discount);
 const orderId=id("ZYX"),reservation=reserveInventory(orderId,product,variant,qty);if(!reservation)return res.status(409).json({error:"Stock berubah, coba lagi"});
 if(promo)promo.usedCount=(Number(promo.usedCount)||0)+1;
 const o={id:orderId,productId:product.id,variantId:variant?.id||null,variantName:variant?.name||"",qty,productName:product.name,price:finalPrice,originalPrice:subtotal,discount,promoCode:promo?.code||"",customerName:name,customerContact:contact,paymentProof:proof,status:"Pending",paymentStatus:proof?"Submitted":"Unpaid",paymentVerified:false,userId:u?.id||null,note:clean(req.body?.note,300),inventoryReservationId:reservation.id,createdAt:new Date().toISOString()};
 orders.unshift(o);recordAnalytics("order_created",{orderId:o.id,productId:o.productId,source:"checkout"});logAction("order.created",{orderId:o.id,productId:o.productId,variantId:o.variantId,qty:o.qty,userId:o.userId});logAction("inventory.reserved",{orderId:o.id,productId:o.productId,variantId:o.variantId,qty:o.qty});notify(o.userId,"Order dibuat",`${o.id} berhasil dibuat. Lanjutkan pembayaran untuk memproses order.` ,"order",{orderId:o.id});persist();res.status(201).json(o);
});
app.get("/api/my/orders",user,(req,res)=>res.json(orders.filter(o=>o.userId===req.user.id)));
app.post("/api/orders/:id/cancel",user,(req,res)=>{const o=orders.find(x=>x.id===req.params.id&&x.userId===req.user.id);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});if(!["Pending","Processing"].includes(o.status))return res.status(400).json({error:"Order ini tidak bisa dibatalkan"});o.status="Cancelled";o.cancelledAt=new Date().toISOString();notify(o.userId,"Order dibatalkan",`${o.id} telah dibatalkan.`,"order",{orderId:o.id});releaseReservation(o.id,"cancel");logAction("order.cancelled",{orderId:o.id,userId:req.user.id});res.json(o)});
app.post("/api/orders/:id/refund",user,(req,res)=>{const o=orders.find(x=>x.id===req.params.id&&x.userId===req.user.id);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});if(o.status!=="Completed")return res.status(400).json({error:"Refund hanya dapat diajukan untuk order selesai"});o.refund={status:"Requested",reason:clean(req.body?.reason,300),createdAt:new Date().toISOString()};notify(o.userId,"Refund diajukan",`Permintaan refund ${o.id} sudah diterima.`,"refund",{orderId:o.id});logAction("refund.requested",{orderId:o.id,userId:req.user.id});res.json(o)});

function orderTimeline(orderId){
  const o=orders.find(x=>x.id===orderId);
  if(!o)return [];
  const rows=activityLogs.filter(x=>x.meta?.orderId===orderId).map(x=>({
    at:x.createdAt,
    action:x.action,
    meta:x.meta
  }));
  const seen=new Set(rows.map(x=>x.action+"|"+x.at));
  const add=(action,at,meta={})=>{if(!at)return;const key=action+"|"+at;if(!seen.has(key)){rows.push({at,action,meta});seen.add(key)}};
  add("order.created",o.createdAt,{orderId});
  add("payment.paid",o.paidAt,{orderId});
  add("order.completed",o.completedAt,{orderId});
  add("order.cancelled",o.cancelledAt,{orderId});
  return rows.sort((a,b)=>Date.parse(a.at)-Date.parse(b.at));
}

app.get("/api/orders/:id/invoice",(req,res)=>{const o=orders.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});res.json({invoiceNumber:"INV-"+o.id.replace(/^ZYX-/i,""),issuedAt:o.createdAt,billTo:o.customerName,contact:o.customerContact,product:o.productName,originalPrice:o.originalPrice,discount:o.originalPrice-o.price,total:o.price,status:o.status,paymentStatus:o.paymentStatus})});
app.get("/api/orders/:id",(req,res)=>{const o=orders.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});res.json(o)});
app.get("/api/orders/:id/timeline",user,(req,res)=>{const o=orders.find(x=>x.id===req.params.id&&x.userId===req.user.id);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});res.json({orderId:o.id,status:o.status,paymentStatus:o.paymentStatus,items:orderTimeline(o.id)});});

app.get("/api/payments/config",(req,res)=>res.json({enabled:BQ_ENABLED,mode:BQ_MODE,provider:"BuatQris"}));

async function buatQrisRequest(fields){
  const body=new URLSearchParams({action:fields.action,account_id:BQ_ACCOUNT_ID,secret_token:BQ_SECRET_TOKEN,...fields.extra});
  const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),12000);
  try{
    const r=await fetch(BQ_API_URL,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body,signal:controller.signal});
    const text=await r.text();let data;try{data=JSON.parse(text)}catch{data={raw:text}}
    if(!r.ok)return {ok:false,status:r.status,data};
    return {ok:true,status:r.status,data};
  }finally{clearTimeout(timeout)}
}

app.post("/api/payments/buatqris/create",async(req,res)=>{
  const ip=req.ip||"unknown";if(!rateLimit("bq-create:"+ip,8,60000))return res.status(429).json({error:"Terlalu banyak permintaan pembayaran. Coba lagi sebentar."});
  if(!BQ_ENABLED)return res.status(503).json({error:"BuatQris belum dikonfigurasi di server",gatewayEnabled:false});
  const orderId=clean(req.body?.orderId,80),o=orders.find(x=>x.id===orderId);
  if(!o)return res.status(404).json({error:"Order tidak ditemukan"});
  const idem=clean(req.headers["idempotency-key"]||req.body?.idempotencyKey,120);
  if(!idem)return res.status(400).json({error:"Idempotency-Key wajib diisi untuk membuat pembayaran"});
  const previous=getIdempotency(idem,orderId);
  if(previous){res.setHeader("X-Idempotent-Replay","true");return res.status(200).json({ok:true,orderId:o.id,payment:previous.payment,replayed:true});}
  if(["Paid","Verified"].includes(o.paymentStatus))return res.status(409).json({error:"Order sudah dibayar",payment:o.payment});
  if(o.status==="Cancelled")return res.status(400).json({error:"Order sudah dibatalkan"});
  try{
    const result=await buatQrisRequest({action:"api_create_qris",extra:{amount:String(o.price),description:`ZYREX ${o.id} - ${o.productName}`.slice(0,200),qris_method:BQ_QRIS_METHOD,fee_by:BQ_FEE_BY}});
    const d=result.data||{},payload=d.data||d;
    if(!result.ok||d.success===false)return res.status(502).json({error:"BuatQris gagal membuat QRIS",providerStatus:result.status,details:typeof d.error==="string"?d.error:undefined});
    const tx=clean(payload.transaction_id||d.transaction_id,120),qrUrl=clean(payload.qr_url||d.qr_url,1000),qrImage=clean(payload.qris_image||d.qris_image,2000000),paymentUrl=clean(payload.payment_url||d.payment_url,1000);
    if(!tx)return res.status(502).json({error:"Response BuatQris tidak memiliki transaction_id"});
    o.transactionId=tx;o.payment={provider:"BuatQris",mode:BQ_MODE,transactionId:tx,qrUrl,qrImage,paymentUrl,status:clean(payload.status||d.status,40)||"pending",createdAt:new Date().toISOString(),attempts:(o.payment?.attempts||0)+1};o.paymentStatus="Pending";
    paymentAudit("created",{orderId:o.id,transactionId:tx,mode:BQ_MODE,attempt:o.payment.attempts,requestId:req.requestId});
    saveIdempotency(idem,orderId,o.payment);
    res.setHeader("X-Idempotent-Replay","false");res.status(201).json({ok:true,orderId:o.id,payment:o.payment});
  }catch(e){res.status(502).json({error:"Tidak bisa menghubungi BuatQris",details:e.name==="AbortError"?"Request timeout":undefined})}
});

app.get("/api/payments/buatqris/status/:orderId",async(req,res)=>{
  if(!BQ_ENABLED)return res.status(503).json({error:"BuatQris belum dikonfigurasi",gatewayEnabled:false});
  const o=orders.find(x=>x.id===req.params.orderId);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});
  const tx=clean(o.payment?.transactionId||o.transactionId,120);if(!tx)return res.status(400).json({error:"Order belum memiliki transaksi QRIS"});
  try{
    const result=await buatQrisRequest({action:"api_check_status",extra:{transaction_id:tx}});
    const d=result.data||{},payload=d.data||d;
    if(!result.ok||d.success===false)return res.status(502).json({error:"Gagal mengecek status BuatQris"});
    const status=clean(payload.status||d.status,40).toLowerCase()||"pending";
    markPaymentStatus(o,status,"status-check",{transactionId:tx,requestId:req.requestId});
    res.json({ok:true,orderId:o.id,transactionId:tx,status:o.paymentStatus,gatewayStatus:status,payment:o.payment});
  }catch(e){res.status(502).json({error:"Tidak bisa mengecek BuatQris",details:e.name==="AbortError"?"Request timeout":undefined})}
});

app.post("/api/payments/buatqris/retry/:orderId",async(req,res)=>{
  const ip=req.ip||"unknown";if(!rateLimit("bq-retry:"+ip,5,60000))return res.status(429).json({error:"Terlalu banyak percobaan pembayaran. Coba lagi sebentar."});
  if(!BQ_ENABLED)return res.status(503).json({error:"BuatQris belum dikonfigurasi",gatewayEnabled:false});
  const o=orders.find(x=>x.id===req.params.orderId);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});
  if(o.status==="Cancelled")return res.status(400).json({error:"Order sudah dibatalkan"});
  if(["Paid","Verified"].includes(o.paymentStatus))return res.status(409).json({error:"Order sudah dibayar",payment:o.payment});
  try{
    const result=await buatQrisRequest({action:"api_create_qris",extra:{amount:String(o.price),description:`ZYREX ${o.id} - ${o.productName}`.slice(0,200),qris_method:BQ_QRIS_METHOD,fee_by:BQ_FEE_BY}});
    const d=result.data||{},payload=d.data||d;if(!result.ok||d.success===false)return res.status(502).json({error:"BuatQris gagal membuat QRIS baru"});
    const tx=clean(payload.transaction_id||d.transaction_id,120),qrUrl=clean(payload.qr_url||d.qr_url,1000),qrImage=clean(payload.qris_image||d.qris_image,2000000),paymentUrl=clean(payload.payment_url||d.payment_url,1000);if(!tx)return res.status(502).json({error:"Response BuatQris tidak memiliki transaction_id"});
    const previousTx=o.payment?.transactionId||o.transactionId||null;o.transactionId=tx;o.payment={provider:"BuatQris",mode:BQ_MODE,transactionId:tx,qrUrl,qrImage,paymentUrl,status:clean(payload.status||d.status,40)||"pending",createdAt:new Date().toISOString(),attempts:(o.payment?.attempts||0)+1,previousTransactionId:previousTx};o.paymentStatus="Pending";paymentAudit("retry",{orderId:o.id,transactionId:tx,previousTransactionId:previousTx,attempt:o.payment.attempts,requestId:req.requestId});res.status(201).json({ok:true,orderId:o.id,payment:o.payment});
  }catch(e){res.status(502).json({error:"Tidak bisa menghubungi BuatQris",details:e.name==="AbortError"?"Request timeout":undefined})}
});
app.get("/api/admin/payments",admin,(req,res)=>{const status=clean(req.query.status,30).toLowerCase();const rows=orders.filter(o=>o.payment?.provider==="BuatQris"&&(!status||String(o.paymentStatus).toLowerCase()===status)).map(o=>({orderId:o.id,transactionId:o.payment?.transactionId||o.transactionId||null,status:o.paymentStatus,gatewayStatus:o.payment?.status||null,attempts:o.payment?.attempts||1,createdAt:o.payment?.createdAt||o.createdAt,checkedAt:o.payment?.checkedAt||null,paidAt:o.paidAt||null}));res.json({count:rows.length,rows});});
app.get("/api/admin/payments/audit",admin,(req,res)=>res.json(paymentLedger.slice(0,200)));
app.post("/api/admin/payments/reconcile",admin,async(req,res)=>{
  if(!BQ_ENABLED)return res.status(503).json({error:"BuatQris belum dikonfigurasi",gatewayEnabled:false});
  const limit=Math.max(1,Math.min(50,Number(req.body?.limit)||20));const candidates=orders.filter(o=>o.payment?.provider==="BuatQris"&&o.payment?.transactionId&&!['Paid','Verified','Expired','Failed'].includes(o.paymentStatus)).slice(0,limit);const results=[];
  for(const o of candidates){try{const r=await buatQrisRequest({action:"api_check_status",extra:{transaction_id:o.payment.transactionId}});const d=r.data||{},payload=d.data||d,status=clean(payload.status||d.status,40).toLowerCase()||"pending";if(r.ok&&d.success!==false)markPaymentStatus(o,status,"reconciliation",{transactionId:o.payment.transactionId});results.push({orderId:o.id,transactionId:o.payment.transactionId,status:r.ok?status:"provider_error",httpStatus:r.status});}catch(e){results.push({orderId:o.id,transactionId:o.payment.transactionId,status:"error",error:e.name==="AbortError"?"timeout":"request_failed"})}}
  paymentAudit("reconciliation",{checked:results.length,requestId:req.requestId});res.json({ok:true,checked:results.length,results});
});
app.post("/api/inquiries",(req,res)=>{
 const ip=req.ip||"unknown";if(!rateLimit("inq:"+ip,5))return res.status(429).json({error:"Terlalu banyak pesan. Coba lagi sebentar."});
 const name=clean(req.body?.name,100),contact=clean(req.body?.contact,120),message=clean(req.body?.message,2000);
 if(!name||!contact||!message)return res.status(400).json({error:"Nama, kontak, dan pesan wajib diisi"});
 const q={id:id("INQ"),name,contact,message,status:"New",createdAt:new Date().toISOString()};inquiries.unshift(q);persist();res.status(201).json({id:q.id,status:q.status});
});

const VALID_GAMES=["signal","reaction","memory","number","typing"];
const GAME_SCORE_CAPS={signal:1000,reaction:1000,memory:500,number:500,typing:100};
const SEASON_MS=30*24*60*60*1000;
function missionWindow(kind,now=Date.now()){
 const d=new Date(now); const key=kind==="weekly"?`${d.getUTCFullYear()}-W${Math.ceil((((now-Date.UTC(d.getUTCFullYear(),0,1))/86400000)+1)/7)}`:d.toISOString().slice(0,10);
 return {key,start:kind==="weekly"?now-6*86400000:Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),d.getUTCDate()),kind};
}
function missionForUser(u,kind){
 const w=missionWindow(kind), mine=scores.filter(x=>x.userId===u.id && Date.parse(x.createdAt)>=w.start);
 const gamesPlayed=new Set(mine.map(x=>x.game)).size, total=mine.length, best=mine.reduce((m,x)=>Math.max(m,x.score),0);
 const target=kind==="weekly"?{plays:10,best:120}:{plays:3,best:50};
 return {id:`${kind}-plays`,kind,title:kind==="weekly"?"Weekly Player":"Daily Player",description:`Play ${target.plays} games`,progress:Math.min(total,target.plays),target:target.plays,complete:total>=target.plays,window:w.key,rewardXp:kind==="weekly"?100:30,extra:{gamesPlayed,best}};
}
app.get("/api/games/missions",user,(req,res)=>res.json({daily:missionForUser(req.user,"daily"),weekly:missionForUser(req.user,"weekly"),season:{key:new Date(Math.floor(Date.now()/SEASON_MS)*SEASON_MS).toISOString().slice(0,10),endsAt:new Date((Math.floor(Date.now()/SEASON_MS)+1)*SEASON_MS).toISOString()}}));
app.get("/api/games/stats",user,(req,res)=>{const mine=scores.filter(x=>x.userId===req.user.id);const stats=Object.fromEntries(VALID_GAMES.map(g=>{const rows=mine.filter(x=>x.game===g);return [g,{plays:rows.length,best:rows.reduce((m,x)=>Math.max(m,x.score),0),average:rows.length?Math.round(rows.reduce((n,x)=>n+x.score,0)/rows.length):0,lastPlayed:rows.at(-1)?.createdAt||null}] }));res.json({totalPlays:mine.length,stats})});

function achievementForScore(game,score){
 const rules=[
  ["first-score","First Score",s=>s>0,10],
  ["signal-25","Signal Hunter",(s,g)=>g==="signal"&&s>=25,25],
  ["reaction-700","Quick Reflex",(s,g)=>g==="reaction"&&s>=700,25],
  ["memory-80","Memory Master",(s,g)=>g==="memory"&&s>=80,25],
  ["number-20","Number Runner",(s,g)=>g==="number"&&s>=20,25],
  ["typing-15","Fast Typist",(s,g)=>g==="typing"&&s>=15,25],
  ["score-100","Century",s=>s>=100,50]
 ];
 return rules.filter(r=>r[2](score,game)).map(r=>({id:r[0],name:r[1],xp:r[3]}));
}
app.post("/api/scores",(req,res)=>{
 const ip=req.ip||"unknown";if(!rateLimit("score:"+ip,30))return res.status(429).json({error:"Score rate limited"});
 const game=clean(req.body?.game,30),score=Math.max(0,Math.min(999999,Number(req.body?.score)||0));
 if(!VALID_GAMES.includes(game)||!Number.isFinite(score))return res.status(400).json({error:"Game tidak valid"});
 if(score>GAME_SCORE_CAPS[game])return res.status(422).json({error:"Score melewati batas validasi server",maxScore:GAME_SCORE_CAPS[game]});
 const u=userFromReq(req),name=clean(u?.name,40)||clean(req.body?.name,40)||"Guest";
 const entry={id:id("SCO"),game,name,score,createdAt:new Date().toISOString(),userId:u?.id||null};
 scores.push(entry);
 const unlocked=[]; if(u){
   const existing=new Set(achievements.filter(a=>a.userId===u.id).map(a=>a.achievementId));
   for(const a of achievementForScore(game,score)) if(!existing.has(a.id)){achievements.push({id:id("ACH"),userId:u.id,achievementId:a.id,name:a.name,xp:a.xp,game,score,createdAt:new Date().toISOString()});unlocked.push(a);notify(u.id,"Achievement unlocked",`${a.name} · +${a.xp} XP`,"achievement",{achievementId:a.id});}
 }
 persist();res.status(201).json({ok:true,score:entry,unlocked});
});
app.get("/api/scores/:game",(req,res)=>{
 const game=clean(req.params.game,30);if(!VALID_GAMES.includes(game))return res.status(400).json({error:"Game tidak valid"});
 const now=Date.now(),week=604800000,month=2592000000;
 const base=scores.filter(x=>x.game===game),rank=(arr)=>arr.sort((a,b)=>b.score-a.score||Date.parse(a.createdAt)-Date.parse(b.createdAt)).slice(0,50).map((x,i)=>({...x,rank:i+1}));
 const global=rank([...base]),weekly=rank(base.filter(x=>now-Date.parse(x.createdAt)<week)),monthly=rank(base.filter(x=>now-Date.parse(x.createdAt)<month));
 res.json({global,weekly,monthly});
});
app.get("/api/community/leaderboard",(req,res)=>{
 const game=clean(req.query.game,30);const period=clean(req.query.period,10)||"global";
 const now=Date.now(),cut=period==="weekly"?604800000:period==="monthly"?2592000000:0;
 let list=scores.filter(x=>(!game||VALID_GAMES.includes(game)&&x.game===game)&&(!cut||now-Date.parse(x.createdAt)<cut));
 const best=new Map();for(const x of list){const key=x.userId||`guest:${x.name}`;const prev=best.get(key);if(!prev||x.score>prev.score)best.set(key,{userId:x.userId,name:x.name,score:x.score,game:x.game,createdAt:x.createdAt});}
 res.json({period,game:game||"all",leaderboard:[...best.values()].sort((a,b)=>b.score-a.score).slice(0,100).map((x,i)=>({...x,rank:i+1}))});
});
app.get("/api/achievements",user,(req,res)=>res.json({achievements:achievements.filter(a=>a.userId===req.user.id)}));
app.post("/api/reviews",(req,res)=>{
 const name=clean(req.body?.name,40)||"Guest",productId=clean(req.body?.productId,20),rating=Math.max(1,Math.min(5,Number(req.body?.rating)||0)),text=clean(req.body?.text,500);
 if(!products.some(p=>p.id===productId)||!rating||!text)return res.status(400).json({error:"Review tidak valid"});
 const r={id:id("REV"),productId,name,rating,text,createdAt:new Date().toISOString()};reviews.unshift(r);persist();res.status(201).json(r);
});
app.get("/api/reviews/:productId",(req,res)=>res.json(reviews.filter(x=>x.productId===req.params.productId).slice(0,30)));

app.post("/api/admin/login",(req,res)=>{
 const ip=req.ip||"unknown",key=`admin-login:${ip}`,now=Date.now(),state=loginFailures.get(key)||{count:0,blockedUntil:0};
 if(state.blockedUntil>now)return res.status(429).json({error:"Terlalu banyak percobaan login. Coba lagi nanti."});
 if(!rateLimit(key,8,60000))return res.status(429).json({error:"Terlalu banyak percobaan login. Coba lagi nanti."});
 if(req.body?.username!==ADMIN_USERNAME||req.body?.password!==ADMIN_PASSWORD){state.count++;if(state.count>=5){state.blockedUntil=now+300000;state.count=0}loginFailures.set(key,state);return res.status(401).json({error:"Username atau password salah"});}
 loginFailures.delete(key);res.json({token:token(ADMIN_USERNAME),expiresIn:28800});
});
app.post("/api/admin/logout",admin,(req,res)=>{const h=req.headers.authorization||"",raw=h.slice(7).split(".")[0];let jti="";try{jti=Buffer.from(raw,"base64url").toString().split(".")[3]||""}catch{};const i=adminSessions.findIndex(x=>x.jti===jti);if(i>=0)adminSessions.splice(i,1);persist();res.json({ok:true});});
app.post("/api/admin/logout-all",admin,(req,res)=>{adminSessions.splice(0);persist();res.json({ok:true});});
app.get("/api/admin/sessions",admin,(req,res)=>res.json(adminSessions.filter(x=>x.expiresAt>Date.now()).map(x=>({jti:x.jti,createdAt:x.createdAt,expiresAt:x.expiresAt}))));
app.get("/api/admin/command-center",admin,(req,res)=>{
 const now=Date.now(),day=86400000,week=7*day;
 const completed=orders.filter(o=>o.status==="Completed"), paid=orders.filter(o=>["Paid","Verified"].includes(o.paymentStatus));
 const pendingPayments=orders.filter(o=>["Pending","Submitted","Unpaid"].includes(o.paymentStatus)&&o.status!=="Cancelled");
 const failedPayments=orders.filter(o=>["Failed","Expired","Rejected"].includes(o.paymentStatus));
 const recent=orders.slice(0,12).map(o=>({id:o.id,productName:o.productName,price:o.price,status:o.status,paymentStatus:o.paymentStatus,createdAt:o.createdAt,customerName:o.customerName}));
 const daily=Array.from({length:7},(_,i)=>{const d=new Date(now-(6-i)*day);const key=d.toISOString().slice(0,10);const dayOrders=orders.filter(o=>o.createdAt.slice(0,10)===key);return {date:key,orders:dayOrders.length,revenue:dayOrders.filter(o=>o.status==="Completed").reduce((s,o)=>s+o.price,0)}});
 const paymentMethods={BuatQris:orders.filter(o=>o.payment?.provider==="BuatQris").length,Manual:orders.filter(o=>!o.payment?.provider).length};
 res.json({version:VERSION,kpis:{orders:orders.length,completed:completed.length,revenue:completed.reduce((s,o)=>s+o.price,0),paid:paid.length,pendingPayments:pendingPayments.length,failedPayments:failedPayments.length,users:users.length,inquiries:inquiries.filter(x=>x.status==="New").length},daily,paymentMethods,recent,paymentConfig:{enabled:BQ_ENABLED,mode:BQ_MODE,provider:"BuatQris"},server:{uptime:Math.round(process.uptime()),dataFile:fs.existsSync(DATA_FILE),timestamp:new Date().toISOString()}});
});
app.get("/api/admin/orders/:id/timeline",admin,(req,res)=>{const o=orders.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});res.json({orderId:o.id,items:orderTimeline(o.id)});});
function parseAnalyticsRange(req){
  const now=Date.now(),maxDays=365;
  const toRaw=req.query.to?new Date(String(req.query.to)+"T23:59:59.999"):new Date(now);
  const fromRaw=req.query.from?new Date(String(req.query.from)+"T00:00:00.000"):new Date(now-29*86400000);
  let from=fromRaw.getTime(),to=toRaw.getTime();
  if(!Number.isFinite(from)||!Number.isFinite(to)){from=now-29*86400000;to=now;}
  if(to<from)[from,to]=[to,from];
  if(to-from>maxDays*86400000)from=to-maxDays*86400000;
  return {from,to,days:Math.max(1,Math.ceil((to-from+1)/86400000))};
}
app.get("/api/admin/analytics",admin,(req,res)=>{
  const {from,to,days}=parseAnalyticsRange(req);
  const inRange=(value)=>{const t=Date.parse(value||"");return Number.isFinite(t)&&t>=from&&t<=to;};
  const rangeOrders=orders.filter(o=>inRange(o.createdAt));
  const paid=rangeOrders.filter(o=>["Paid","Verified"].includes(o.paymentStatus)||o.paidAt&&inRange(o.paidAt));
  const completed=rangeOrders.filter(o=>o.status==="Completed");
  const revenue=completed.reduce((sum,o)=>sum+Number(o.price||0),0);
  const aov=completed.length?Math.round(revenue/completed.length):0;
  const customerMap=new Map();
  for(const o of paid){const key=o.userId||String(o.customerContact||o.customerName||"").toLowerCase();if(key)customerMap.set(key,(customerMap.get(key)||0)+1);}
  const repeatCustomers=[...customerMap.values()].filter(n=>n>=2).length;
  const uniqueCustomers=customerMap.size;
  const events=analyticsEvents.filter(e=>inRange(e.createdAt));
  const traffic={pageViews:events.filter(e=>e.event==="page_view").length,storeViews:events.filter(e=>e.event==="store_view").length,productViews:events.filter(e=>e.event==="product_view").length,checkoutStarts:events.filter(e=>e.event==="checkout_start").length};
  const games={scores:scores.filter(x=>inRange(x.createdAt)).length,players:new Set(scores.filter(x=>inRange(x.createdAt)).map(x=>x.userId||x.name).filter(Boolean)).size,byGame:{}};
  for(const x of scores.filter(x=>inRange(x.createdAt))){games.byGame[x.game]=games.byGame[x.game]||{plays:0,players:new Set()};games.byGame[x.game].plays++;games.byGame[x.game].players.add(x.userId||x.name||"anon");}
  for(const [k,v] of Object.entries(games.byGame))v.players=v.players.size;
  const userActivity=new Map();
  for(const u of users){if(!inRange(u.createdAt))continue;userActivity.set(u.id,{createdAt:u.createdAt,active:false});}
  for(const x of scores){if(x.userId&&userActivity.has(x.userId)&&inRange(x.createdAt))userActivity.get(x.userId).active=true;}
  for(const o of rangeOrders){if(o.userId&&userActivity.has(o.userId))userActivity.get(o.userId).active=true;}
  const newUsers=[...userActivity.values()],activeNewUsers=newUsers.filter(x=>x.active).length;
  const retentionRate=newUsers.length?Math.round(activeNewUsers/newUsers.length*100):0;
  const daily=Array.from({length:days},(_,i)=>{const start=new Date(from+i*86400000),end=new Date(Math.min(to,start.getTime()+86400000-1)),os=orders.filter(o=>{const t=Date.parse(o.createdAt||"");return t>=start.getTime()&&t<=end.getTime();}),es=analyticsEvents.filter(e=>{const t=Date.parse(e.createdAt||"");return t>=start.getTime()&&t<=end.getTime();});return {date:start.toISOString().slice(0,10),orders:os.length,revenue:os.filter(o=>o.status==="Completed").reduce((sum,o)=>sum+Number(o.price||0),0),paid:os.filter(o=>["Paid","Verified"].includes(o.paymentStatus)||o.paidAt).length,visits:es.filter(e=>e.event==="page_view").length};});
  res.json({version:VERSION,range:{from:new Date(from).toISOString(),to:new Date(to).toISOString(),days},kpis:{orders:rangeOrders.length,completed:completed.length,revenue,aov,paid:paid.length,uniqueCustomers,repeatCustomers,repeatCustomerRate:uniqueCustomers?Math.round(repeatCustomers/uniqueCustomers*100):0,newUsers:newUsers.length,retentionRate},traffic,games,daily});
});

app.get("/api/admin/analytics/export",admin,(req,res)=>{
  const {from,to}=parseAnalyticsRange(req);
  const inRange=(v)=>{const t=Date.parse(v||"");return Number.isFinite(t)&&t>=from&&t<=to;};
  const rows=orders.filter(o=>inRange(o.createdAt));
  const header=["order_id","created_at","product","status","payment_status","customer","price"];
  const csv=[header,...rows.map(o=>[o.id,o.createdAt,o.productName,o.status,o.paymentStatus,o.customerName,o.price])].map(r=>r.map(v=>'"'+String(v??"").replaceAll('"','""')+'"').join(",")).join("\n");
  res.setHeader("Content-Type","text/csv; charset=utf-8");res.setHeader("Content-Disposition",`attachment; filename="zyrex-analytics-${new Date(from).toISOString().slice(0,10)}-${new Date(to).toISOString().slice(0,10)}.csv"`);res.send(csv);
});

app.get("/api/admin/intelligence",admin,(req,res)=>{
 const now=Date.now(),day=86400000,from=now-30*day,events=analyticsEvents.filter(e=>Date.parse(e.createdAt)>=from);
 const count=e=>events.filter(x=>x.event===e).length;
 const orders30=orders.filter(o=>Date.parse(o.createdAt)>=from),paid30=orders30.filter(o=>["Paid","Verified"].includes(o.paymentStatus)||o.paidAt);
 const revenue30=orders30.filter(o=>o.status==="Completed").reduce((s,o)=>s+Number(o.price||0),0);
 const checkout=count("checkout_start"),created=count("order_created")||orders30.length,success=count("payment_success")||paid30.length;
 const funnel=[{name:"Page views",value:count("page_view")},{name:"Store views",value:count("store_view")},{name:"Checkout starts",value:checkout},{name:"Orders created",value:created},{name:"Payments successful",value:success}];
 const byProduct=products.map(p=>{const pe=events.filter(e=>e.meta?.productId===p.id);const po=orders30.filter(o=>o.productId===p.id);return {id:p.id,name:p.name,views:pe.filter(e=>e.event==="product_view").length,orders:po.length,paid:po.filter(o=>["Paid","Verified"].includes(o.paymentStatus)||o.paidAt).length,revenue:po.filter(o=>o.status==="Completed").reduce((s,o)=>s+Number(o.price||0),0),stock:p.stock??0}});
 const payments=orders30.filter(o=>o.paymentStatus);const paymentSuccess=payments.filter(o=>["Paid","Verified"].includes(o.paymentStatus)).length;
 const paymentSuccessRate=payments.length?Math.round(paymentSuccess/payments.length*100):0;
 const alerts=[];products.filter(p=>Number(p.stock??0)<=5).forEach(p=>alerts.push({level:"warning",title:"Low stock",message:`${p.name} tersisa ${p.stock??0}.`}));if(BQ_ENABLED===false)alerts.push({level:"info",title:"BuatQris belum aktif",message:"Isi BQ_ACCOUNT_ID dan BQ_SECRET_TOKEN di environment server."});if(payments.length&&paymentSuccessRate<70)alerts.push({level:"warning",title:"Payment success rate rendah",message:`Success rate 30 hari terakhir ${paymentSuccessRate}%.`});if(orders30.length&&paid30.length===0)alerts.push({level:"warning",title:"Belum ada pembayaran sukses",message:"Belum ada order paid dalam 30 hari terakhir."});
 const daily=Array.from({length:30},(_,i)=>{const d=new Date(now-(29-i)*day),key=d.toISOString().slice(0,10),os=orders30.filter(o=>o.createdAt.slice(0,10)===key);return {date:key,orders:os.length,revenue:os.filter(o=>o.status==="Completed").reduce((s,o)=>s+Number(o.price||0),0),paid:os.filter(o=>["Paid","Verified"].includes(o.paymentStatus)||o.paidAt).length}});
 res.json({version:VERSION,periodDays:30,kpis:{orders:orders30.length,revenue:revenue30,paid:paid30.length,paymentSuccessRate,checkoutStarts:checkout,conversionRate:checkout?Math.round(created/checkout*100):0,paymentConversion:created?Math.round(success/created*100):0},funnel,byProduct,daily,alerts,events:events.length});
});
app.get("/api/admin/stats",admin,(req,res)=>{
 const revenue=orders.filter(o=>o.status==="Completed").reduce((s,o)=>s+o.price,0);
 const byProduct=products.map(p=>({name:p.name,orders:orders.filter(o=>o.productId===p.id).length,revenue:orders.filter(o=>o.productId===p.id&&o.status==="Completed").reduce((s,o)=>s+o.price,0)}));
 res.json({totalOrders:orders.length,revenue,projects:3,activeServices:products.length,inquiries:inquiries.filter(x=>x.status==="New").length,users:"Local",scores:scores.length,reviews:reviews.length,byProduct});
});
app.get("/api/admin/orders",admin,(req,res)=>res.json(orders));
app.patch("/api/admin/orders/:id",admin,(req,res)=>{const o=orders.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});const allowed=["Pending","Processing","Completed","Cancelled"];if(!allowed.includes(req.body?.status))return res.status(400).json({error:"Status tidak valid"});o.status=req.body.status;if(req.body.status==="Completed")o.completedAt=new Date().toISOString();notify(o.userId,"Status order diperbarui",`${o.id} sekarang ${o.status}.`,"order",{orderId:o.id,status:o.status});logAction("order.status",{orderId:o.id,status:o.status});persist();res.json(o)});
app.get("/api/admin/inquiries",admin,(req,res)=>res.json(inquiries));
app.patch("/api/admin/inquiries/:id",admin,(req,res)=>{const q=inquiries.find(x=>x.id===req.params.id);if(!q)return res.status(404).json({error:"Inquiry tidak ditemukan"});const allowed=["New","Contacted","Closed"];if(!allowed.includes(req.body?.status))return res.status(400).json({error:"Status tidak valid"});q.status=req.body.status;persist();res.json(q)});
app.get("/api/admin/activity",admin,(req,res)=>res.json(activityLogs.slice(0,100)));
app.get("/api/admin/users",admin,(req,res)=>res.json(users.map(publicUser)));
app.get("/api/admin/promos",admin,(req,res)=>res.json(promos));
app.post("/api/admin/promos",admin,(req,res)=>{const code=clean(req.body?.code,30).toUpperCase(),type=req.body?.type==="fixed"?"fixed":"percent",value=Math.max(0,Number(req.body?.value)||0);if(!code||!value||promos.some(x=>x.code===code))return res.status(400).json({error:"Promo tidak valid atau sudah ada"});const p={code,type,value,active:true,maxUses:Math.max(0,Math.floor(Number(req.body?.maxUses)||0)),usedCount:0,perUserLimit:Math.max(0,Math.floor(Number(req.body?.perUserLimit)||0)),minSubtotal:Math.max(0,Number(req.body?.minSubtotal)||0),startsAt:req.body?.startsAt||null,endsAt:req.body?.endsAt||null};promos.push(p);logAction("promo.created",{code});res.status(201).json(p)});
app.patch("/api/admin/promos/:code",admin,(req,res)=>{const p=promos.find(x=>x.code===req.params.code.toUpperCase());if(!p)return res.status(404).json({error:"Promo tidak ditemukan"});if(req.body.active!==undefined)p.active=Boolean(req.body.active);if(req.body.value!==undefined)p.value=Math.max(0,Number(req.body.value)||0);if(req.body.maxUses!==undefined)p.maxUses=Math.max(0,Math.floor(Number(req.body.maxUses)||0));if(req.body.perUserLimit!==undefined)p.perUserLimit=Math.max(0,Math.floor(Number(req.body.perUserLimit)||0));if(req.body.minSubtotal!==undefined)p.minSubtotal=Math.max(0,Number(req.body.minSubtotal)||0);if(req.body.startsAt!==undefined)p.startsAt=req.body.startsAt||null;if(req.body.endsAt!==undefined)p.endsAt=req.body.endsAt||null;logAction("promo.updated",{code:p.code});res.json(p)});
app.delete("/api/admin/promos/:code",admin,(req,res)=>{const i=promos.findIndex(x=>x.code===req.params.code.toUpperCase());if(i<0)return res.status(404).json({error:"Promo tidak ditemukan"});const code=promos[i].code;promos.splice(i,1);logAction("promo.deleted",{code});res.json({ok:true})});
app.get("/api/admin/products",admin,(req,res)=>res.json(products));
app.patch("/api/admin/products/:id/stock",admin,(req,res)=>{const p=products.find(x=>x.id===req.params.id);const stock=Math.max(0,Math.floor(Number(req.body?.stock)));if(!p||!Number.isFinite(stock))return res.status(400).json({error:"Stock tidak valid"});p.stock=stock;p.stockUpdatedAt=new Date().toISOString();logAction("product.stock",{productId:p.id,stock});res.json(p)});
app.patch("/api/admin/products/:id/publish",admin,(req,res)=>{const p=products.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:"Product tidak ditemukan"});p.published=req.body?.published!==false;logAction("product.publish",{productId:p.id,published:p.published});res.json(p)});

app.get("/api/admin/inventory/movements",admin,(req,res)=>res.json(inventoryMovements.slice(0,200)));
app.get("/api/admin/inventory/reservations",admin,(req,res)=>res.json(inventoryReservations.slice(0,200)));
app.post("/api/admin/inventory/release-expired",admin,(req,res)=>{let n=0;for(const r of inventoryReservations){if(r.status==="reserved"&&r.expiresAt<=Date.now()){const o=orders.find(x=>x.id===r.orderId);if(o&&!['Paid','Verified','Completed','Cancelled'].includes(o.paymentStatus)&&o.status!=="Cancelled"){releaseReservation(o.id,"reservation_expired");o.paymentStatus="Expired";notify(o.userId,"Reservation kedaluwarsa",`Stock untuk ${o.id} dilepas karena pembayaran belum selesai.` ,"order",{orderId:o.id});n++;}}}persist();res.json({ok:true,released:n})});
app.post("/api/admin/products/:id/variants",admin,(req,res)=>{const p=products.find(x=>x.id===req.params.id),name=clean(req.body?.name,60),priceDelta=Number(req.body?.priceDelta)||0,stock=Math.max(0,Math.floor(Number(req.body?.stock)||0));if(!p||!name)return res.status(400).json({error:"Varian tidak valid"});p.variants=p.variants||[];const v={id:id("VAR"),name,priceDelta,stock};p.variants.push(v);inventoryMove(p.id,v.id,stock,"variant_initial_stock");persist();res.status(201).json(v)});
app.patch("/api/admin/products/:id/variants/:variantId",admin,(req,res)=>{const p=products.find(x=>x.id===req.params.id),v=variantFor(p,req.params.variantId);if(!v)return res.status(404).json({error:"Varian tidak ditemukan"});if(req.body.name!==undefined)v.name=clean(req.body.name,60)||v.name;if(req.body.priceDelta!==undefined)v.priceDelta=Number(req.body.priceDelta)||0;if(req.body.stock!==undefined){const next=Math.max(0,Math.floor(Number(req.body.stock)||0));inventoryMove(p.id,v.id,next-v.stock,"admin_adjustment");v.stock=next}persist();res.json(v)});
app.delete("/api/admin/products/:id/variants/:variantId",admin,(req,res)=>{const p=products.find(x=>x.id===req.params.id),i=p?.variants?.findIndex(v=>v.id===req.params.variantId);if(!p||i<0)return res.status(404).json({error:"Varian tidak ditemukan"});p.variants.splice(i,1);persist();res.json({ok:true})});

app.post("/api/admin/products",admin,(req,res)=>{const name=clean(req.body?.name,80),category=clean(req.body?.category,30),price=Math.max(0,Number(req.body?.price)||0),description=clean(req.body?.description,300);if(!name||!category||!price||!description)return res.status(400).json({error:"Data produk belum lengkap"});const p={id:id("P"),name,category,price,description,featured:Boolean(req.body?.featured),published:req.body?.published!==false,stock:Math.max(0,Math.floor(Number(req.body?.stock)||99)),variants:Array.isArray(req.body?.variants)?req.body.variants:[],startAt:req.body?.startAt||null,endAt:req.body?.endAt||null};products.push(p);persist();res.status(201).json(p)});
app.patch("/api/admin/products/:id",admin,(req,res)=>{const p=products.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:"Product tidak ditemukan"});if(req.body.name!==undefined)p.name=clean(req.body.name,80);if(req.body.description!==undefined)p.description=clean(req.body.description,300);if(req.body.category!==undefined)p.category=clean(req.body.category,30);if(req.body.price!==undefined)p.price=Math.max(0,Number(req.body.price)||0);if(req.body.featured!==undefined)p.featured=Boolean(req.body.featured);if(req.body.published!==undefined)p.published=Boolean(req.body.published);if(req.body.startAt!==undefined)p.startAt=req.body.startAt||null;if(req.body.endAt!==undefined)p.endAt=req.body.endAt||null;persist();res.json(p)});
app.delete("/api/admin/products/:id",admin,(req,res)=>{const i=products.findIndex(x=>x.id===req.params.id);if(i<0)return res.status(404).json({error:"Product tidak ditemukan"});products.splice(i,1);persist();res.json({ok:true})});


app.patch("/api/admin/orders/:id/payment",admin,(req,res)=>{const o=orders.find(x=>x.id===req.params.id);if(!o)return res.status(404).json({error:"Order tidak ditemukan"});o.paymentVerified=Boolean(req.body?.verified);o.paymentStatus=o.paymentVerified?"Verified":"Rejected";if(o.paymentVerified){o.paidAt=o.paidAt||new Date().toISOString();o.status=o.status==="Cancelled"?o.status:"Processing";notify(o.userId,"Pembayaran diverifikasi",`Pembayaran ${o.id} telah diverifikasi admin.` ,"payment",{orderId:o.id});}logAction("payment.manual",{orderId:o.id,verified:o.paymentVerified});persist();res.json(o)});
app.get("/api/admin/analytics",admin,(req,res)=>{const completed=orders.filter(o=>o.status==="Completed");const byDay={};orders.forEach(o=>{const d=o.createdAt.slice(0,10);byDay[d]=(byDay[d]||0)+1});res.json({orders:orders.length,completed:completed.length,revenue:completed.reduce((s,o)=>s+o.price,0),users:users.length,products:products.length,byDay})});
app.get("/api/admin/backup",admin,(req,res)=>{makeBackup();res.download(DATA_FILE,"zyrex-backup.json")});
app.get("/api/admin/backups",admin,(req,res)=>{const files=fs.readdirSync(BACKUP_DIR).filter(f=>f.endsWith(".json")).sort().reverse().slice(0,20);res.json(files.map(f=>({name:f,size:fs.statSync(path.join(BACKUP_DIR,f)).size,createdAt:fs.statSync(path.join(BACKUP_DIR,f)).mtime.toISOString()})))});
app.get("/api/admin/settings",admin,(req,res)=>res.json({...systemSettings,schemaVersion:SCHEMA_VERSION,backupCount:fs.readdirSync(BACKUP_DIR).filter(f=>f.endsWith(".json")).length}));
app.patch("/api/admin/settings",admin,(req,res)=>{if(req.body.maintenance!==undefined)systemSettings.maintenance=Boolean(req.body.maintenance);if(req.body.allowRegistrations!==undefined)systemSettings.allowRegistrations=Boolean(req.body.allowRegistrations);if(req.body.announcement!==undefined)systemSettings.announcement=clean(req.body.announcement,500);persist();logAction("system.settings",{...systemSettings});res.json({...systemSettings,schemaVersion:SCHEMA_VERSION})});
app.post("/api/admin/restore",admin,(req,res)=>{try{const payload=req.body;if(!payload||typeof payload!=="object"||!Array.isArray(payload.products)||!Array.isArray(payload.orders)||!Array.isArray(payload.users))return res.status(400).json({error:"Backup tidak valid"});makeBackup();products.splice(0,products.length,...payload.products);orders.splice(0,orders.length,...payload.orders);inquiries.splice(0,inquiries.length,...(payload.inquiries||[]));scores.splice(0,scores.length,...(payload.scores||[]));reviews.splice(0,reviews.length,...(payload.reviews||[]));users.splice(0,users.length,...payload.users);sessions.splice(0,sessions.length,...(payload.sessions||[]));promos.splice(0,promos.length,...(payload.promos||defaults.promos));activityLogs.splice(0,activityLogs.length,...(payload.activityLogs||[]));passwordResets.splice(0,passwordResets.length,...(payload.passwordResets||[]));notifications.splice(0,notifications.length,...(payload.notifications||[]));analyticsEvents.splice(0,analyticsEvents.length,...(payload.analyticsEvents||[]));connections.splice(0,connections.length,...(payload.connections||[]));challenges.splice(0,challenges.length,...(payload.challenges||[]));Object.assign(systemSettings,payload.systemSettings||{});persist();logAction("system.restore",{schemaVersion:payload.schemaVersion||1});res.json({ok:true,schemaVersion:SCHEMA_VERSION})}catch(e){res.status(400).json({error:"Restore gagal"})}});
app.get("/api/admin/export/:type",admin,(req,res)=>{
 const type=clean(req.params.type,20);const rows=type==="orders"?orders:type==="inquiries"?inquiries:type==="products"?products:null;
 if(!rows)return res.status(400).json({error:"Export type tidak valid"});
 const keys=[...new Set(rows.flatMap(x=>Object.keys(x)))];
 const csv=[keys.join(","),...rows.map(r=>keys.map(k=>`"${String(r[k]??"").replaceAll('"','""')}"`).join(","))].join("\n");
 res.setHeader("Content-Type","text/csv; charset=utf-8");res.setHeader("Content-Disposition",`attachment; filename=zyrex-${type}.csv`);res.send(csv);
});

app.get("/api/admin/database",admin,async(req,res)=>{const reachable=await pingDatabase();res.json({version:VERSION,database:{...databaseStatus(),reachable},dataFile:fs.existsSync(DATA_FILE),schemaVersion:SCHEMA_VERSION});});
app.use((req,res,next)=>{if(req.path.startsWith("/api/"))return res.status(404).json({error:"API route not found"});next()});
app.use((err,req,res,next)=>{console.error(err);try{logAction("server.error",{message:String(err.message||err).slice(0,300),path:req.path})}catch{}res.status(500).json({error:"Internal server error"})});
const dbResult=await initDatabase({getState:snapshot,applyState});
// Persist the effective state after loading PostgreSQL or the local JSON fallback.
persist();
let shuttingDown=false;
async function shutdown(signal){if(shuttingDown)return;shuttingDown=true;console.log(`ZYREX ${signal}: graceful shutdown`);clearInterval(backupTimer);clearInterval(paymentTimer);clearInterval(cleanupTimer);server.close(async()=>{try{const {closeDatabase}=await import("./db.js");await closeDatabase()}catch{}process.exit(0)})}
async function reservationExpirySweep(){let changed=0;for(const r of inventoryReservations){if(r.status!=="reserved"||r.expiresAt>Date.now())continue;const o=orders.find(x=>x.id===r.orderId);if(o&&["Paid","Verified","Completed","Cancelled"].includes(o.paymentStatus))continue;if(releaseReservation(r.orderId,"reservation_expired")){if(o){o.paymentStatus="Expired";o.paymentExpiredAt=new Date().toISOString();notify(o.userId,"Reservation kedaluwarsa",`Stock untuk ${o.id} dilepas karena pembayaran belum selesai.` ,"order",{orderId:o.id});logAction("reservation.expired",{orderId:o.id})}changed++}}if(changed)persist();return changed}

function paymentExpirySweep(){
  const now=Date.now(),ttl=30*60*1000;let changed=0;
  for(const o of orders){if(o.payment?.provider!=="BuatQris"||!o.payment?.transactionId)continue;if(["Paid","Verified","Expired","Failed"].includes(o.paymentStatus))continue;const created=Date.parse(o.payment.createdAt||o.createdAt);if(Number.isFinite(created)&&now-created>ttl){o.paymentStatus="Expired";o.payment.status="expired";o.payment.expiredAt=new Date().toISOString();notify(o.userId,"Pembayaran kedaluwarsa",`QRIS untuk ${o.id} sudah kedaluwarsa.` ,"payment",{orderId:o.id});paymentAudit("expired",{orderId:o.id,transactionId:o.payment.transactionId,source:"expiry-worker"});changed++;}}
  for(let i=paymentIdempotency.length-1;i>=0;i--)if(paymentIdempotency[i].expiresAt<=now)paymentIdempotency.splice(i,1);
  if(changed)persist();
}
const backupTimer=setInterval(()=>makeBackup(),24*60*60*1000);backupTimer.unref();
const paymentTimer=setInterval(()=>{void paymentExpirySweep();void reservationExpirySweep()},5*60*1000);paymentTimer.unref();
const cleanupTimer=setInterval(()=>{const now=Date.now();for(const [k,v] of requestLog)if(!v.some(t=>now-t<60000))requestLog.delete(k);for(const [k,v] of loginFailures)if(v.blockedUntil<now&&v.count===0)loginFailures.delete(k);for(let i=adminSessions.length-1;i>=0;i--)if(adminSessions[i].expiresAt<=now)adminSessions.splice(i,1);for(let i=passwordResets.length-1;i>=0;i--)if(passwordResets[i].expiresAt<=now)passwordResets.splice(i,1);persist()},10*60*1000);cleanupTimer.unref();
process.on("SIGTERM",()=>void shutdown("SIGTERM"));process.on("SIGINT",()=>void shutdown("SIGINT"));
server.listen(PORT,"0.0.0.0",()=>console.log(`ZYREX ${VERSION} running on ${PORT} · DB ${dbResult.connected?"PostgreSQL":"JSON fallback"}`));
