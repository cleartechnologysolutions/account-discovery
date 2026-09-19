import {test} from 'node:test';
import assert from 'node:assert/strict';
import {domainOf,scopedEmail,extractPage,candidate,rankPatterns,csvCell} from '../public/core.js';
import {classifyMicrosoft,microsoftCheck} from '../worker/microsoft.js';
import {handle,sign,verify,publicIP,robotsAllows,scopedURL} from '../worker/index.js';
test('scope normalization and SSRF boundaries',()=>{
 assert.equal(domainOf('https://EXAMPLE.com/'),'example.com');
 for(const x of ['127.0.0.1','localhost','foo.local','foo.test','a.com@evil.net','a.com:443','*.example.com'])assert.equal(domainOf(x),'');
 assert.equal(scopedEmail('Jane@Example.com','example.com'),'jane@example.com');
 assert.equal(scopedEmail('a@sub.example.com','example.com'),'');
 for(const ip of ['127.0.0.1','10.4.0.1','169.254.169.254','172.17.0.1','192.168.1.1','100.100.100.200','198.18.1.1','::1','fe80::1','fd00::1','2001:db8::1'])assert.equal(publicIP(ip),false,ip);
 assert.equal(publicIP('8.8.8.8'),true);assert.equal(publicIP('2606:4700:4700::1111'),true);
 for(const u of ['http://example.com/','https://evil.com/','https://example.com.evil.com/','https://user:pass@example.com/','https://example.com:8443/'])assert.throws(()=>scopedURL(u,'example.com'));
 assert.equal(scopedURL('https://www.example.com/team','example.com').hostname,'www.example.com');
});
test('public email extraction, structured people, team headings, source links and guessing',()=>{
 const html=`<h2>Our Leadership</h2><h3>Jane Smith</h3><h3>Read More</h3><p>Email jane.smith@example.com; outsider@other.com</p><a href="mailto:rjones@example.com">Email</a><a href="/team/jane">Bio</a><a href="https://evil.com/team">Other</a><script type="application/ld+json">{"@type":"Person","name":"Robert Jones","email":"rjones@example.com"}</script>`;
 const d=extractPage(html,'https://example.com/team','example.com');assert.deepEqual(new Set(d.emails.map(e=>e.email)),new Set(['jane.smith@example.com','rjones@example.com']));assert.deepEqual(new Set(d.people.map(p=>p.name)),new Set(['Jane Smith','Robert Jones']));assert.deepEqual(d.links,['https://example.com/team/jane']);
 assert.equal(candidate('José O’Neil','flast','example.com'),'joneil@example.com');
 assert.equal(candidate('OneName','flast','example.com'),'');assert.equal(candidate('王 明','flast','example.com'),'');
 assert.equal(rankPatterns(['Jane Smith'],d.emails,'example.com')[0].pattern,'first.last');
 assert.equal(csvCell('=HYPERLINK("evil")'),'"\'=HYPERLINK(""evil"")"');
});
test('robots exclusion, specificity and explicit exceptions',()=>{
 assert.equal(robotsAllows('User-agent: *\nDisallow: /','/team'),false);
 assert.equal(robotsAllows('User-agent: *\nDisallow: /team\nAllow: /team/public','/team/public/jane'),true);
 assert.equal(robotsAllows('User-agent: OtherBot\nDisallow: /\nUser-agent: *\nDisallow: /admin','/team'),true);
 assert.equal(robotsAllows('User-agent: *\nDisallow: /*?secret=','/team?secret=x'),false);
});
test('Microsoft tri-state classification never promotes ambiguous responses',()=>{
 assert.equal(classifyMicrosoft({IfExistsResult:0}).status,'likely-exists');assert.equal(classifyMicrosoft({IfExistsResult:1}).status,'likely-nonexistent');
 for(const data of [{IfExistsResult:5},{IfExistsResult:6},{IfExistsResult:'0'},{},{IfExistsResult:0,Credentials:{FederationRedirectUrl:'https://sso.example.com'}},{IfExistsResult:0,ThrottleStatus:1},{IfExistsResult:0,CaptchaRequired:true}]){assert.equal(classifyMicrosoft(data).status,'inconclusive');assert.equal(classifyMicrosoft(data).stop,true);}
 for(const status of [302,403,429,500])assert.equal(classifyMicrosoft({},status).stop,true);
});
test('Microsoft uses username-only discovery, refuses redirects and oversized data',async()=>{
 const r=await microsoftCheck('jane@example.com',async(url,init)=>{assert.equal(url,'https://login.microsoftonline.com/common/GetCredentialType');assert.equal(init.redirect,'manual');const payload=JSON.parse(init.body);assert.equal(payload.username,'jane@example.com');assert.ok(!('password' in payload));return Response.json({IfExistsResult:0,Credentials:{}});});assert.equal(r.status,'likely-exists');
 assert.equal((await microsoftCheck('jane@example.com',async()=>new Response('challenge',{status:403}))).stop,true);
 assert.equal((await microsoftCheck('jane@example.com',async()=>new Response('x'.repeat(70000),{headers:{'content-type':'application/json'}}))).status,'inconclusive');
});
test('signed sessions and calibration tokens cannot be forged or reused across domains',async()=>{
 const token=await sign({type:'session',exp:Date.now()+60000},'sufficiently-long-test-secret');assert.ok(await verify(token,'sufficiently-long-test-secret'));assert.equal(await verify(token,'another-long-secret'),null);assert.equal(await verify(token+'tamper','sufficiently-long-test-secret'),null);assert.equal(await verify(await sign({exp:1},'sufficiently-long-test-secret'),'sufficiently-long-test-secret'),null);
});
function env(){const binding={limit:async()=>({success:true})};return {ADMIN_PASSWORD:'testing-password-12345678',ALLOWED_DOMAINS:'example.com,second.com',LOGIN_LIMIT:binding,LOGIN_GLOBAL:binding,APP_LIMIT:binding,MS_LIMIT:binding,ASSETS:{fetch:async()=>new Response('asset')}};}
async function fixture(){const e=env();const token=await sign({type:'session',id:'test-session',exp:Date.now()+100000},e.ADMIN_PASSWORD);const req=(path,body,origin='https://app.example')=>new Request('https://app.example/api/'+path,{method:'POST',headers:{Origin:origin,'Content-Type':'application/json',Cookie:'__Host-ad_session='+token},body:JSON.stringify(body)});return {e,req};}
test('authorization, CSRF, scope and calibration enforced before external lookups',async()=>{
 const {e,req}=await fixture();const never=()=>{throw new Error('Unexpected outbound request');};
 await assert.rejects(handle(req('page',{domain:'evil.com',url:'https://evil.com/'}),e,never),/not in ALLOWED_DOMAINS/);
 await assert.rejects(handle(req('ms/check',{domain:'example.com',email:'jane@example.com'}),e,never),/Calibrate/);
 await assert.rejects(handle(req('page',{domain:'example.com'},'https://evil.com'),e,never),/origin/);
 const unauth=new Request('https://app.example/api/page',{method:'POST',headers:{Origin:'https://app.example','Content-Type':'application/json'},body:'{}'});await assert.rejects(handle(unauth,e,never),/sign in/);
 const cal=await sign({type:'calibration',domain:'second.com',sid:'test-session',exp:Date.now()+10000,method:'credentialtype-v1'},e.ADMIN_PASSWORD);await assert.rejects(handle(req('ms/check',{domain:'example.com',email:'jane@example.com',calibration:cal}),e,never),/Calibrate/);
});
test('calibration fails closed on catchall and enables only matching control responses',async()=>{
 const {e,req}=await fixture();let count=0;
 const bad=await handle(req('ms/calibrate',{domain:'example.com',knownEmail:'jane@example.com'}),e,async()=>{count++;return Response.json({IfExistsResult:0});});assert.equal((await bad.json()).passed,false);assert.equal(count,1);
 const good=await handle(req('ms/calibrate',{domain:'example.com',knownEmail:'jane@example.com'}),e,async(url,init)=>Response.json({IfExistsResult:JSON.parse(init.body).username==='jane@example.com'?0:1}));const calibration=await good.json();assert.equal(calibration.passed,true);
 const result=await handle(req('ms/check',{domain:'example.com',email:'jane@example.com',calibration:calibration.calibration}),e,async()=>Response.json({IfExistsResult:0}));assert.equal((await result.json()).status,'likely-exists');
 await assert.rejects(handle(req('ms/check',{domain:'example.com',email:'jane@second.com',calibration:calibration.calibration}),e,async()=>{throw Error('must not fetch');}),/selected domain/);
});
test('website crawl respects robots and rejects private DNS and external redirects',async()=>{
 const {e,req}=await fixture();
 const dns=url=>url.includes('type=AAAA')?Response.json({Status:0}):Response.json({Status:0,Answer:[{type:1,data:'8.8.8.8'}]});
 const blocked=async url=>url.includes('dns-query')?dns(url):new Response('User-agent: *\nDisallow: /',{headers:{'content-type':'text/plain'}});
 await assert.rejects(handle(req('page',{domain:'example.com',url:'https://example.com/team'}),e,blocked),/robots/);
 await assert.rejects(handle(req('page',{domain:'example.com',url:'https://example.com/team'}),e,async()=>Response.json({Status:0,Answer:[{type:1,data:'127.0.0.1'}]})),/public IP/);
 const redirect=async url=>url.includes('dns-query')?dns(url):new Response(null,{status:302,headers:{location:'https://evil.com/'}});
 await assert.rejects(handle(req('page',{domain:'example.com',url:'https://example.com/team'}),e,redirect),/selected domain/);
 const ok=async url=>url.includes('dns-query')?dns(url):url.endsWith('/robots.txt')?new Response('',{status:404}):new Response('<h2>Jane Smith</h2><p>jsmith@example.com</p>',{headers:{'content-type':'text/html'}});
 const result=await (await handle(req('page',{domain:'example.com',url:'https://example.com/team'}),e,ok)).json();assert.equal(result.emails[0].email,'jsmith@example.com');assert.equal(result.people[0].name,'Jane Smith');
});
test('optional web search returns sourced addresses and unconfirmed profile names',async()=>{
 const {e,req}=await fixture();e.BRAVE_API_KEY='test-key';let calls=0;
 const r=await handle(req('search',{domain:'example.com',company:'Example Company'}),e,async(url,init)=>{calls++;assert.ok(url.startsWith('https://api.search.brave.com/'));assert.equal(init.headers['X-Subscription-Token'],'test-key');return Response.json({web:{results:[{url:'https://www.linkedin.com/in/jane-smith',title:'Jane Smith - Example Company | LinkedIn',description:'Example Company. jsmith@example.com'},{url:'javascript:evil',title:'ignore'}]}});});const data=await r.json();assert.equal(calls,3);assert.equal(data.people[0].name,'Jane Smith');assert.match(data.people[0].evidence,/unconfirmed/);assert.equal(data.sources.length,1);
});
test('Microsoft diagnostics identify each flag and never expose upstream secrets',()=>{
 for(const [field,value] of [['ThrottleStatus',1],['Throttled',true],['CaptchaRequired',true],['IsFederatedNS',true]]){
  const r=classifyMicrosoft({IfExistsResult:1,[field]:value});assert.match(r.evidence,new RegExp(field));assert.equal(r.diagnostics[field],value);assert.equal(r.status,'inconclusive');
 }
 const r=classifyMicrosoft({IfExistsResult:0,Error:'secret-error-body',Credentials:{FederationRedirectUrl:'https://secret.example/token'},Token:'secret-token'});
 const json=JSON.stringify(r);assert.ok(!json.includes('secret'));assert.equal(r.diagnostics.hasError,true);assert.equal(r.diagnostics.hasFederationRedirect,true);
 assert.equal(classifyMicrosoft({IfExistsResult:1,ThrottleStatus:0}).status,'likely-nonexistent');
 assert.equal(classifyMicrosoft({IfExistsResult:1,ThrottleStatus:'0'}).diagnostics.ThrottleStatus,'0');
 assert.equal(classifyMicrosoft(null,403).reason,'http_forbidden');assert.equal(classifyMicrosoft(null,429).reason,'http_throttled');
});
