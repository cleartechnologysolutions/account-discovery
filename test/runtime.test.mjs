import {test} from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
const {Miniflare}=await import(process.env.MINIFLARE_MODULE||'miniflare');
const root=fileURLToPath(new URL('../',import.meta.url));
test('actual Worker runtime serves app, protects APIs, sets cookies and applies rate limits',async()=>{
 const bindings={ADMIN_PASSWORD:'test-password-long-enough',ALLOWED_DOMAINS:'example.com'};
 const mf=new Miniflare({modules:true,modulesRules:[{type:'ESModule',include:['**/*.js']}],modulesRoot:root,scriptPath:root+'worker/index.js',compatibilityDate:'2026-05-15',host:'127.0.0.1',bindings,
 ratelimits:Object.fromEntries(['LOGIN_LIMIT','LOGIN_GLOBAL','APP_LIMIT','MS_LIMIT'].map(name=>[name,{simple:{limit:3,period:60}}])),assets:{directory:root+'public',binding:'ASSETS',routerConfig:{has_user_worker:true,invoke_user_worker_ahead_of_assets:true}}});
 const origin='https://discovery.example';const post=(path,body,cookie='',site=origin)=>mf.dispatchFetch(origin+'/api/'+path,{method:'POST',headers:{origin:site,'content-type':'application/json',cookie},body:JSON.stringify(body)});
 try{
  const page=await mf.dispatchFetch(origin+'/');assert.equal(page.status,200);assert.match(await page.text(),/Account Discovery/);assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/);
  const initial=await (await mf.dispatchFetch(origin+'/api/session')).json();assert.equal(initial.authenticated,false);assert.deepEqual(initial.domains,[]);
  assert.equal((await post('page',{domain:'example.com'})).status,401);
  assert.equal((await post('login',{password:bindings.ADMIN_PASSWORD},'', 'https://evil.example')).status,403);
  assert.equal((await post('login',{password:'wrong'})).status,401);
  const login=await post('login',{password:bindings.ADMIN_PASSWORD});assert.equal(login.status,200);const cookie=login.headers.get('set-cookie');assert.match(cookie,/HttpOnly; Secure; SameSite=Strict/);
  const current=await (await mf.dispatchFetch(origin+'/api/session',{headers:{cookie:cookie.split(';')[0]}})).json();assert.deepEqual(current.domains,['example.com']);
  assert.equal((await post('page',{domain:'other.com',url:'https://other.com'},cookie)).status,403);
  assert.equal((await post('ms/check',{domain:'example.com',email:'jane@example.com'},cookie)).status,409);
  const logout=await post('logout',{},cookie);assert.match(logout.headers.get('set-cookie'),/Max-Age=0/);
  await post('login',{password:'wrong'});assert.equal((await post('login',{password:'wrong'})).status,429);
 }finally{await mf.dispose();}
});
