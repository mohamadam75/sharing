const enc = new TextEncoder();
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8', 'cache-control':'no-store', ...headers}});
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = s => Uint8Array.from(atob(s), c=>c.charCodeAt(0));
export async function hashText(s){return b64(await crypto.subtle.digest('SHA-256',enc.encode(s)))}
export async function passwordHash(password, salt){const key=await crypto.subtle.importKey('raw',enc.encode(password),{name:'PBKDF2'},false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(salt),iterations:150000,hash:'SHA-256'},key,256);return b64(bits)}
export function response(data,status=200,headers={}){return json(data,status,headers)}
export function cookie(name,value,maxAge){return name+'='+value+'; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age='+maxAge}
export function clearCookie(){return 'flash_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'}
export async function currentUser(request,env){const raw=request.headers.get('Cookie')||'';const token=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith('flash_session='))?.slice(14);if(!token)return null;const tokenHash=await hashText(token);const row=await env.DB.prepare('SELECT users.id, users.username FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?').bind(tokenHash,new Date().toISOString()).first();return row||null}
export function randomToken(){const bytes=crypto.getRandomValues(new Uint8Array(32));return b64(bytes).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}
export function isSameOrigin(request){const origin=request.headers.get('Origin');if(!origin)return true;return origin===new URL(request.url).origin}

export function storageConfig(env){
  let base=String(env.SUPABASE_URL||''); while(base.endsWith('/'))base=base.slice(0,-1);
  const key=env.SUPABASE_SERVICE_ROLE_KEY;
  const bucket=env.SUPABASE_BUCKET||'my-flash-files';
  if(!base||!key||!bucket)throw new Error('storage_not_configured');
  return {base,key,bucket};
}
export async function storageRequest(env,path,options={}){
  const {base,key}=storageConfig(env);
  const headers=new Headers(options.headers||{});
  headers.set('apikey',key);
  headers.set('Authorization','Bearer '+key);
  headers.set('cache-control','no-store');
  return fetch(base+'/storage/v1'+path,{...options,headers});
}
export {json};