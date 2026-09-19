// This is an undocumented sign-in discovery endpoint, NOT a supported directory API.
// No passwords, token requests, Autologon, or authentication fallback are used.
// Deliberately allowlist diagnostics: never expose upstream tokens, URLs or error text.
function diagnosticValue(value) {
  if(value === undefined) return 'absent';
  if(value === null || typeof value === 'boolean' || typeof value === 'number') return value;
  if(typeof value === 'string' && /^(?:true|false|-?\d{1,6})$/i.test(value)) return value;
  return `[${typeof value}]`;
}
export function classifyMicrosoft(data, status=200) {
  const object=data && typeof data==='object' ? data : {};
  const props=object.Credentials || {};
  const diagnostics={httpStatus:status};
  for(const key of ['IfExistsResult','ThrottleStatus','Throttled','CaptchaRequired','IsFederatedNS']) diagnostics[key]=diagnosticValue(object[key]);
  diagnostics.hasFederationRedirect=!!props.FederationRedirectUrl;
  diagnostics.hasError=!!(object.Error || object.error);
  const result=(evidence,reason,state='inconclusive')=>({status:state,stop:state==='inconclusive',evidence,reason,diagnostics});
  if(status===429) return result('Microsoft returned HTTP 429 (too many requests). Stop checks and retry later.','http_throttled');
  if(status===403) return result('Microsoft returned HTTP 403 (request forbidden). No account conclusion was made.','http_forbidden');
  if(status!==200) return result(`Microsoft returned HTTP ${status}; no account conclusion was made.`,'http_error');
  if(!data || typeof data!=='object') return result('Microsoft did not return a usable JSON discovery object.','invalid_response');
  const code=data.IfExistsResult;
  const reasons=[];
  if(data.ThrottleStatus) reasons.push('ThrottleStatus is set');
  if(data.Throttled) reasons.push('Throttled is set');
  if(data.CaptchaRequired) reasons.push('CaptchaRequired is set');
  if(data.Error || data.error) reasons.push('an error field is set');
  if(data.IsFederatedNS) reasons.push('IsFederatedNS is set');
  if(props.FederationRedirectUrl) reasons.push('a federation redirect is present');
  if(reasons.length) return result('Response flagged: '+reasons.join('; ')+'. See diagnostic fields; no account conclusion was made.','response_flags');
  if(code===0) return result('Microsoft discovery returned IfExistsResult=0. This is an account-existence signal, not proof of a mailbox or access.','exists_signal','likely-exists');
  if(code===1) return result('Microsoft discovery returned IfExistsResult=1. Email aliases and alternate login names can differ.','nonexistent_signal','likely-nonexistent');
  return result(`Unrecognized or ambiguous Microsoft response${Number.isInteger(code)?` (IfExistsResult=${code})`:''}.`,'ambiguous_code');
}
export async function microsoftCheck(email, fetcher=fetch) {
  try {
    const res=await fetcher('https://login.microsoftonline.com/common/GetCredentialType',{
      method:'POST',redirect:'manual',signal:AbortSignal.timeout(12000),
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      body:JSON.stringify({username:email,isOtherIdpSupported:true,isRemoteNGCSupported:true,isFidoSupported:true,checkPhones:false,isCookieBannerShown:false,isAccessPassSupported:true})
    });
    // Never forward upstream HTML, tokens, canaries or redirects to the browser.
    if(res.status!==200) { await res.body?.cancel(); return classifyMicrosoft(null,res.status); }
    if(!res.headers.get('content-type')?.includes('json')) { await res.body?.cancel(); return {...classifyMicrosoft(null),reason:'non_json',evidence:'Microsoft returned a non-JSON response. No account conclusion was made.'}; }
    const reader=res.body.getReader();let chunks=[],length=0;
    while(true){const {done,value}=await reader.read();if(done)break; length+=value.length;if(length>65536){await reader.cancel();return {...classifyMicrosoft(null),reason:'oversized_response',evidence:'Microsoft response exceeded the diagnostic size limit.'};}chunks.push(value);}
    const all=new Uint8Array(length);let pos=0;for(const c of chunks){all.set(c,pos);pos+=c.length;}
    return classifyMicrosoft(JSON.parse(new TextDecoder().decode(all)));
  } catch { return {status:'inconclusive',stop:true,evidence:'Microsoft lookup timed out or could not be read. No account conclusion was made.'}; }
}
