// This is an undocumented sign-in discovery endpoint, NOT a supported directory API.
// No passwords, token requests, Autologon, or authentication fallback are used.
export function classifyMicrosoft(data, status=200) {
  if(status===429 || status===403) return {status:'inconclusive', stop:true, evidence:`Microsoft blocked or throttled the request (HTTP ${status}).`};
  if(status!==200 || !data || typeof data!=='object') return {status:'inconclusive',stop:true,evidence:'Microsoft did not return a usable discovery response.'};
  const code=data.IfExistsResult;
  const props=data.Credentials || {};
  if(data.ThrottleStatus || data.Throttled || data.CaptchaRequired || data.Error || data.error || data.IsFederatedNS || props.FederationRedirectUrl) return {status:'inconclusive',stop:true,evidence:'Federated, challenged, throttled, or error response; account existence cannot be established.'};
  if(code===0) return {status:'likely-exists',stop:false,evidence:'Microsoft discovery returned IfExistsResult=0. This is an account-existence signal, not proof of a mailbox or access.'};
  if(code===1) return {status:'likely-nonexistent',stop:false,evidence:'Microsoft discovery returned IfExistsResult=1. Email aliases and alternate login names can differ.'};
  return {status:'inconclusive',stop:true,evidence:`Unrecognized or ambiguous Microsoft response${Number.isInteger(code)?` (IfExistsResult=${code})`:''}.`};
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
    if(!res.headers.get('content-type')?.includes('json')) { await res.body?.cancel(); return classifyMicrosoft(null); }
    const reader=res.body.getReader();let chunks=[],length=0;
    while(true){const {done,value}=await reader.read();if(done)break; length+=value.length;if(length>65536){await reader.cancel();return classifyMicrosoft(null);}chunks.push(value);}
    const all=new Uint8Array(length);let pos=0;for(const c of chunks){all.set(c,pos);pos+=c.length;}
    return classifyMicrosoft(JSON.parse(new TextDecoder().decode(all)));
  } catch { return {status:'inconclusive',stop:true,evidence:'Microsoft lookup timed out or could not be read. No account conclusion was made.'}; }
}
