export function domainOf(value) {
  let d = String(value || '').trim().toLowerCase();
  if (/^https?:\/\//.test(d)) { try { d = new URL(d).hostname; } catch { return ''; } }
  d = d.replace(/\.$/, '');
  if (d.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d)) return '';
  if (/\.(?:local|localhost|internal|test|invalid|arpa)$/.test(d)) return '';
  return d;
}
export function scopedEmail(value, domain) {
  const e = String(value || '').trim().toLowerCase();
  return e.length <= 254 && /^[a-z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-z0-9.-]+$/.test(e) && e.split('@')[1] === domain ? e : '';
}
export function textOnly(value) {
  return String(value || '').replace(/<[^>]*>/g, ' ').replace(/&(?:nbsp|amp|quot|apos|lt|gt);|&#(?:\d+|x[0-9a-f]+);/gi, m => {
    const known = {'&nbsp;':' ', '&amp;':'&', '&quot;':'"', '&apos;':"'", '&lt;':'<', '&gt;':'>'};
    if (known[m]) return known[m];
    const n = m[2]?.toLowerCase() === 'x' ? parseInt(m.slice(3),16) : parseInt(m.slice(2),10);
    return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : '';
  }).replace(/\s+/g, ' ').trim();
}
const banned = /\b(about|team|meet|contact|leadership|services|management|executive|director|president|our|read|learn|more|privacy|policy|support|sales|office|careers|news|staff|people|company|board|cookie|business|solutions|customer|chief|officer|view|all|employee|welcome|get|started|resources|group|join|member|senior|partner|global)\b/i;
export function plausibleName(value) {
  const s = textOnly(value);
  const parts = s.split(/\s+/);
  return s.length <= 70 && parts.length >= 2 && parts.length <= 4 && !banned.test(s) && parts.every(p => /^[\p{L}][\p{L}\p{M}'’.-]*$/u.test(p)) ? s : '';
}
export const patterns = {
  'first.last': (f,l) => `${f}.${l}`,
  'flast': (f,l) => f[0]+l,
  'firstlast': (f,l) => f+l,
  'first': (f,l) => f,
  'firstl': (f,l) => f+l[0],
  'first_last': (f,l) => `${f}_${l}`,
  'last.first': (f,l) => `${l}.${f}`,
  'lastf': (f,l) => l+f[0]
};
export function candidate(name, pattern, domain) {
  const parts = String(name).trim().split(/\s+/).map(x => x.normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z]/gi,'').toLowerCase());
  if(parts.length < 2 || !parts[0] || !parts.at(-1) || !patterns[pattern]) return '';
  return scopedEmail(patterns[pattern](parts[0], parts.at(-1))+'@'+domain, domain);
}
export function rankPatterns(people, emails, domain) {
  const set = new Set(emails.map(e => typeof e === 'string' ? e : e.email));
  return Object.keys(patterns).map(pattern => ({pattern, matches: people.filter(p => set.has(candidate(typeof p==='string'?p:p.name,pattern,domain))).length})).sort((a,b)=>b.matches-a.matches);
}
export function extractPage(html, url, domain) {
  const emails = new Set(), people = new Map(), links = new Set();
  const noScripts = html.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi,' ');
  const decoded = textOnly(noScripts).replace(/\s*\[at\]\s*/gi,'@').replace(/\s*\[dot\]\s*/gi,'.');
  for (const m of decoded.matchAll(/[a-z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,63}/gi)) {
    const e = scopedEmail(m[0].replace(/[.,;]+$/, ''),domain); if(e) emails.add(e);
  }
  for (const m of noScripts.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
    try {
      const u = new URL(textOnly(m[1]),url);
      if(u.protocol==='mailto:') { const e=scopedEmail(decodeURIComponent(u.pathname),domain); if(e)emails.add(e); }
      if(u.protocol==='https:' && [domain,'www.'+domain].includes(u.hostname) && !u.username && !u.password && !u.port && /team|people|staff|leadership|about|contact|management|bio|directory/i.test(u.pathname)) {
        u.hash='';u.search=''; links.add(u.href);
      }
    } catch {}
  }
  function walk(x,depth=0) {
    if(depth>12 || !x || typeof x!=='object') return;
    if(Array.isArray(x)){ for(const v of x.slice(0,300))walk(v,depth+1); return; }
    const type=Array.isArray(x['@type'])?x['@type']:[x['@type']];
    if(type.includes('Person')) {
      const name=plausibleName(x.name || [x.givenName,x.familyName].filter(Boolean).join(' '));
      const email=scopedEmail(String(x.email||'').replace(/^mailto:/,''),domain);
      if(name)people.set(name.toLowerCase(),{name,email,source:url,evidence:'Structured person — affiliation needs review'});
      if(email)emails.add(email);
    }
    for(const value of Object.values(x))walk(value,depth+1);
  }
  for(const m of html.matchAll(/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi))try{walk(JSON.parse(m[1]));}catch{}
  if(/team|people|staff|leadership|management|directory/i.test(new URL(url).pathname)) {
    for(const m of noScripts.matchAll(/<h[2-4]\b[^>]*>([\s\S]*?)<\/h[2-4]>/gi)) {
      const name=plausibleName(m[1]); if(name && !people.has(name.toLowerCase()))people.set(name.toLowerCase(),{name,email:'',source:url,evidence:'Possible person from team-page heading — review'});
    }
  }
  return {emails:[...emails].slice(0,200).map(email=>({email,source:url,evidence:'Published on website'})),people:[...people.values()].slice(0,200),links:[...links].slice(0,24)};
}
export function csvCell(value) {
  let s=String(value ?? ''); if(/^[\s]*[=+@-]/.test(s))s="'"+s;
  return '"'+s.replaceAll('"','""')+'"';
}
