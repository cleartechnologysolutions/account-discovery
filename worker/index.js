import {domainOf,scopedEmail,extractPage,textOnly,plausibleName} from '../public/core.js';
import {microsoftCheck} from './microsoft.js';
const enc=new TextEncoder();
const fail=(message,status=400)=>Object.assign(new Error(message),{status});
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers}});
function wrap(res) {
  const r=new Response(res.body,res);r.headers.set('X-Content-Type-Options','nosniff');r.headers.set('Referrer-Policy','no-referrer');r.headers.set('X-Frame-Options','DENY');
  r.headers.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'");
  r.headers.set('Permissions-Policy','camera=(), microphone=(), geolocation=()');r.headers.set('Cache-Control','no-store');return r;
}
export function allowedDomains(env){return [...new Set(String(env.ALLOWED_DOMAINS||'').split(/[\s,;]+/).map(domainOf).filter(Boolean))].slice(0,100);}
const b64=bytes=>btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
const unb64=s=>Uint8Array.from(atob(s.replaceAll('-','+').replaceAll('_','/')),x=>x.charCodeAt(0));
async function key(secret){return crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);}
export async function sign(payload,secret){const text=b64(enc.encode(JSON.stringify(payload)));const sig=await crypto.subtle.sign('HMAC',await key(secret),enc.encode(text));return text+'.'+b64(new Uint8Array(sig));}
export async function verify(token,secret){try{const [text,sig,extra]=String(token||'').split('.');if(extra || !text || !sig)return null;if(!await crypto.subtle.verify('HMAC',await key(secret),unb64(sig),enc.encode(text)))return null;const p=JSON.parse(new TextDecoder().decode(unb64(text)));return p.exp>Date.now()?p:null;}catch{return null;}}
async function passwordEqual(a,b){const [x,y]=await Promise.all([a,b].map(s=>crypto.subtle.digest('SHA-256',enc.encode(String(s)))));const u=new Uint8Array(x),v=new Uint8Array(y);let d=0;for(let i=0;i<u.length;i++)d|=u[i]^v[i];return d===0;}
async function limit(binding,k){if(!binding)throw fail('Rate limit binding is missing. Redeploy using the included configuration.',503);if(!(await binding.limit({key:k})).success)throw fail('Request limit reached. Stop and wait at least one minute before trying again.',429);}
export async function boundedText(res,max=2*1024*1024){if(Number(res.headers.get('content-length'))>max){await res.body?.cancel();throw fail('Source exceeds the page-size limit.',422);}if(!res.body)return '';const reader=res.body.getReader(),chunks=[];let n=0;while(true){const{done,value}=await reader.read();if(done)break;n+=value.length;if(n>max){await reader.cancel();throw fail('Source exceeds the page-size limit.',422);}chunks.push(value);}const out=new Uint8Array(n);let i=0;for(const c of chunks){out.set(c,i);i+=c.length;}return new TextDecoder().decode(out);}
export function publicIP(ip){
  if(ip.includes(':'))return /^[23][0-9a-f]{3}:/i.test(ip) && !/^2001:(?:db8|0|10|20):/i.test(ip);
  const p=ip.split('.').map(Number);if(p.length!==4 || p.some(n=>!Number.isInteger(n)||n<0||n>255))return false;
  const[a,b,c]=p;return !(a===0||a===10||a===127||a>=224||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&(b===168||b===0||b===2))||(a===198&&(b===18||b===19||(b===51&&c===100)))||(a===203&&b===0&&c===113)||(a===100&&b>=64&&b<=127));
}
async function resolvePublic(host,fetcher){
  const ips=[];
  for(const type of ['A','AAAA']){
    const r=await fetcher('https://cloudflare-dns.com/dns-query?name='+encodeURIComponent(host)+'&type='+type,{headers:{Accept:'application/dns-json'},redirect:'manual',signal:AbortSignal.timeout(8000)});
    if(!r.ok)throw fail('Could not verify website DNS.',422);const d=JSON.parse(await boundedText(r,65536));
    if(![0,3].includes(d.Status))throw fail('Website DNS lookup was inconclusive.',422);
    for(const a of d.Answer||[])if([1,28].includes(a.type))ips.push(a.data);
  }
  if(!ips.length||ips.some(ip=>!publicIP(ip)))throw fail('Website must resolve exclusively to public IP addresses.',422);
}
export function scopedURL(value,domain){let u;try{u=new URL(value);}catch{throw fail('Enter a complete HTTPS page URL.');}if(u.protocol!=='https:' || u.username || u.password || u.port || ![domain,'www.'+domain].includes(u.hostname))throw fail('Pages must use HTTPS on the selected domain or its www host.',403);u.hash='';return u;}
async function websiteFetch(value,domain,fetcher){let u=scopedURL(value,domain);for(let i=0;i<4;i++){
  await resolvePublic(u.hostname,fetcher);
  const r=await fetcher(u.href,{redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'User-Agent':'AccountDiscovery/1.0 (authorized public business contact assessment)','Accept':'text/html,text/plain;q=0.8'}});
  if([301,302,303,307,308].includes(r.status)){const location=r.headers.get('location');await r.body?.cancel();if(!location)throw fail('Website returned an empty redirect.',422);u=scopedURL(new URL(location,u).href,domain);continue;}
  return {res:r,url:u.href};
 }throw fail('Too many website redirects.',422);}
export function robotsAllows(text,path){
  const groups=[];let current=null,hasRules=false;
  for(const raw of text.split(/\r?\n/)){const line=raw.split('#')[0].trim(),i=line.indexOf(':');if(i<0)continue;const field=line.slice(0,i).trim().toLowerCase(),value=line.slice(i+1).trim();
    if(field==='user-agent'){if(!current||hasRules){current={agents:[],rules:[]};groups.push(current);hasRules=false;}current.agents.push(value.toLowerCase());}
    else if(current&&['allow','disallow'].includes(field)){hasRules=true;if(value)current.rules.push({allow:field==='allow',path:value});}
  }
  const specific=groups.filter(g=>g.agents.some(a=>a==='accountdiscovery'));const selected=specific.length?specific:groups.filter(g=>g.agents.includes('*'));
  const matches=[];for(const g of selected)for(const rule of g.rules){const tail=rule.path.endsWith('$');const raw=tail?rule.path.slice(0,-1):rule.path;const re='^'+raw.split('*').map(x=>x.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('.*')+(tail?'$':'');if(new RegExp(re).test(path))matches.push({...rule,size:raw.replaceAll('*','').length});}
  matches.sort((a,b)=>b.size-a.size || Number(b.allow)-Number(a.allow));return !matches.length||matches[0].allow;
}
async function discoverPage(value,domain,fetcher){
  const u=scopedURL(value,domain);
  const robots=await websiteFetch(u.origin+'/robots.txt',domain,fetcher);
  if(robots.res.status!==404){if(!robots.res.ok){await robots.res.body?.cancel();throw fail('robots.txt could not be checked; page skipped.',422);}const txt=await boundedText(robots.res,128000);if(!robotsAllows(txt,u.pathname+u.search))throw fail('Page excluded by robots.txt.',422);}
  else await robots.res.body?.cancel();
  const result=await websiteFetch(u.href,domain,fetcher);
  if(result.url!==u.href){const dest=new URL(result.url);const rules=await websiteFetch(dest.origin+'/robots.txt',domain,fetcher);if(rules.res.status===404)await rules.res.body?.cancel();else if(!rules.res.ok||!robotsAllows(await boundedText(rules.res,128000),dest.pathname+dest.search))throw fail('Redirect destination excluded or robots unavailable.',422);}
  if(!result.res.ok){await result.res.body?.cancel();throw fail('Website returned HTTP '+result.res.status+'.',422);}
  if(!/text\/html|application\/xhtml\+xml/i.test(result.res.headers.get('content-type')||'')){await result.res.body?.cancel();throw fail('This version reads HTML pages. PDF or script-rendered pages require a separate import.',422);}
  return {...extractPage(await boundedText(result.res),result.url,domain),source:result.url,checkedAt:new Date().toISOString()};
}
async function searchWeb(domain,company,env,fetcher){
  if(!env.BRAVE_API_KEY)throw fail('Internet search is not configured. Add BRAVE_API_KEY or use website discovery and name imports.',422);
  const name=String(company||domain).replace(/["\\\n\r]/g,' ').slice(0,100);
  const queries=[`"@${domain}"`,`"${name}" team staff leadership`,`site:linkedin.com/in "${name}"`];
  const sources=[],emails=[],people=[];
  for(const q of queries){const r=await fetcher('https://api.search.brave.com/res/v1/web/search?q='+encodeURIComponent(q)+'&count=10',{headers:{Accept:'application/json','X-Subscription-Token':env.BRAVE_API_KEY},redirect:'manual',signal:AbortSignal.timeout(12000)});
    if(!r.ok){await r.body?.cancel();throw fail('Internet-search provider returned HTTP '+r.status+'. Check its key, quota, and subscription.',422);}
    const d=JSON.parse(await boundedText(r,1000000));for(const item of d.web?.results||[]){let u;try{u=new URL(item.url);}catch{continue;}if(u.protocol!=='https:')continue;
      const title=textOnly(item.title).slice(0,250),description=textOnly(item.description).slice(0,1000);
      sources.push({url:u.href,title,description});
      if((u.hostname==='linkedin.com'||u.hostname.endsWith('.linkedin.com'))&&u.pathname.startsWith('/in/')){
        const person=plausibleName(title.split(/\s[-–—|]\s/)[0]);
        if(person)people.push({name:person,email:'',source:u.href,evidence:'Search-index profile title — employer and current employment unconfirmed'});
      }
      for(const m of (title+' '+description).matchAll(/[a-z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,63}/gi)){const e=scopedEmail(m[0].replace(/[.,;]+$/,''),domain);if(e)emails.push({email:e,source:u.href,evidence:'Search snippet — open source to confirm'});}
    }
  }
  return {sources:[...new Map(sources.map(x=>[x.url,x])).values()],emails,people};
}
async function bodyJSON(request){try{return JSON.parse(await boundedText(request,32000));}catch(e){if(e.status)throw e;throw fail('Invalid JSON request.');}}
function domainGuard(input,env){const d=domainOf(input);if(!d||!allowedDomains(env).includes(d))throw fail('This domain is not in ALLOWED_DOMAINS. Add the authorized client domain in Cloudflare Settings.',403);return d;}
async function sessionFrom(req,env){const token=req.headers.get('cookie')?.match(/(?:^|;\s*)__Host-ad_session=([^;]+)/)?.[1];const s=await verify(token,env.ADMIN_PASSWORD);return s?.type==='session'?s:null;}
export async function handle(request,env,fetcher=fetch){
  const url=new URL(request.url),path=url.pathname;
  if(!path.startsWith('/api/')){if(!['GET','HEAD'].includes(request.method))return json({error:'Method not allowed'},405);return env.ASSETS.fetch(request);}
  const configured=typeof env.ADMIN_PASSWORD==='string'&&env.ADMIN_PASSWORD.length>=16;
  if(path==='/api/session'&&request.method==='GET'){const s=configured?await sessionFrom(request,env):null;return json({configured,authenticated:!!s,domains:s?allowedDomains(env):[],webSearch:s?!!env.BRAVE_API_KEY:false,build:'1.0.0'});}
  if(request.method!=='POST')throw fail('Method not allowed.',405);
  if(request.headers.get('origin')!==url.origin || !request.headers.get('content-type')?.startsWith('application/json'))throw fail('Request origin or content type is not allowed.',403);
  if(!configured)throw fail('Add ADMIN_PASSWORD as a Cloudflare secret with at least 16 characters.',503);
  if(path==='/api/login'){
    await limit(env.LOGIN_LIMIT,request.headers.get('CF-Connecting-IP')||'unknown');await limit(env.LOGIN_GLOBAL,'all');const b=await bodyJSON(request);
    if(!await passwordEqual(b.password,env.ADMIN_PASSWORD))throw fail('Incorrect password.',401);
    const s=await sign({type:'session',id:crypto.randomUUID(),exp:Date.now()+8*3600000},env.ADMIN_PASSWORD);
    return json({ok:true},200,{'Set-Cookie':`__Host-ad_session=${s}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`});
  }
  const session=await sessionFrom(request,env);if(!session)throw fail('Please sign in again.',401);
  if(path==='/api/logout')return json({ok:true},200,{'Set-Cookie':'__Host-ad_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'});
  await limit(env.APP_LIMIT,session.id);
  const b=await bodyJSON(request),domain=domainGuard(b.domain,env);
  if(path==='/api/page')return json(await discoverPage(b.url,domain,fetcher));
  if(path==='/api/search')return json(await searchWeb(domain,b.company,env,fetcher));
  if(path.startsWith('/api/ms/')) {
    await limit(env.MS_LIMIT,domain);
    if(path==='/api/ms/calibrate'){
      const email=scopedEmail(b.knownEmail,domain);if(!email)throw fail('Enter a known existing sign-in name in the selected domain.');
      const negative='assessment-control-'+crypto.randomUUID().replaceAll('-','')+'@'+domain;
      const neg=await microsoftCheck(negative,fetcher);
      if(neg.status!=='likely-nonexistent')return json({passed:false,evidence:'Random nonexistent control was not distinguished. Microsoft checks are unavailable for this domain with this method.',negative:neg});
      const pos=await microsoftCheck(email,fetcher);
      if(pos.status!=='likely-exists')return json({passed:false,evidence:'Known existing control was not recognized. Check its sign-in name; this method may be unsupported for the domain.',positive:pos,negative:neg});
      const expires=Date.now()+30*60000;
      const calibration=await sign({type:'calibration',domain,sid:session.id,exp:expires,method:'credentialtype-v1'},env.ADMIN_PASSWORD);
      return json({passed:true,calibration,expires,evidence:'Existing and random nonexistent controls returned different expected responses. Results remain indicative, not directory verification.'});
    }
    const cal=await verify(b.calibration,env.ADMIN_PASSWORD);
    if(cal?.type!=='calibration'||cal.domain!==domain||cal.sid!==session.id||cal.method!=='credentialtype-v1')throw fail('Calibrate Microsoft checks for this domain first. Calibration lasts 30 minutes.',409);
    if(path==='/api/ms/control'){
      const r=await microsoftCheck('assessment-control-'+crypto.randomUUID().replaceAll('-','')+'@'+domain,fetcher);
      return json({passed:r.status==='likely-nonexistent',...r,checkedAt:new Date().toISOString()});
    }
    if(path==='/api/ms/check'){
      const email=scopedEmail(b.email,domain);if(!email)throw fail('Email must belong to the selected domain.');
      return json({email,...await microsoftCheck(email,fetcher),checkedAt:new Date().toISOString(),method:'Microsoft GetCredentialType; calibrated inference'});
    }
  }
  throw fail('Unknown endpoint.',404);
}
export default {async fetch(request,env){try{return wrap(await handle(request,env));}catch(e){return wrap(json({error:e.status?e.message:'Request failed. No account conclusion was made.'},e.status||500));}}};
