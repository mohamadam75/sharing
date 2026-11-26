const enc = new TextEncoder();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const json = (data,status=200,headers={}) => new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
async function hashText(s){return b64(await crypto.subtle.digest('SHA-256',enc.encode(s)))}
async function passwordHash(password,salt){const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(salt),iterations:150000,hash:'SHA-256'},key,256);return b64(bits)}
function randomToken(){const bytes=crypto.getRandomValues(new Uint8Array(32));return b64(bytes).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}
function cookie(name,value,maxAge){return name+'='+value+'; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age='+maxAge}
function clearCookie(){return 'flash_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'}
function sameOrigin(request){const origin=request.headers.get('Origin');return !origin||origin===new URL(request.url).origin}
async function currentUser(request,env){const raw=request.headers.get('Cookie')||'';const token=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith('flash_session='))?.slice(14);if(!token)return null;return await env.DB.prepare('SELECT users.id, users.username FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?').bind(await hashText(token),new Date().toISOString()).first()}
function storageConfig(env){let base=String(env.SUPABASE_URL||'');while(base.endsWith('/'))base=base.slice(0,-1);const key=env.SUPABASE_SERVICE_ROLE_KEY;const bucket=env.SUPABASE_BUCKET||'my-flash-files';if(!base||!key)return null;return {base,key,bucket}}
async function storageRequest(env,path,options={}){const cfg=storageConfig(env);if(!cfg)throw new Error('storage_not_configured');const headers=new Headers(options.headers||{});headers.set('apikey',cfg.key);headers.set('Authorization','Bearer '+cfg.key);return fetch(cfg.base+'/storage/v1'+path,{...options,headers})}
const inlineTypes=['image/png','image/jpeg','image/gif','image/webp','image/avif','audio/mpeg','audio/ogg','audio/wav','audio/webm','audio/mp4','video/mp4','video/webm','video/ogg','application/pdf'];
function safeName(value){return String(value||'file').split('').map(c=>(c==='/'||c==='\\'||c.charCodeAt(0)<32)?'_':c).join('').slice(0,240)}
async function handle(request,env){
 const url=new URL(request.url),path=url.pathname,method=request.method;
 if(path.startsWith('/api/')){
  if(path==='/api/auth/register'&&method==='POST'){
   if(!sameOrigin(request))return json({error:'درخواست نامعتبر است'},403);
   let body;try{body=await request.json()}catch{return json({error:'اطلاعات نامعتبر است'},400)}
   const username=String(body.username||'').trim().toLowerCase(),password=String(body.password||'');
   if(!/^[\p{L}\p{N}_.-]{3,24}$/u.test(username))return json({error:'نام کاربری باید ۳ تا ۲۴ حرف یا عدد باشد'},400);
   if(password.length<8||password.length>128)return json({error:'رمز عبور باید حداقل ۸ کاراکتر باشد'},400);
   const salt=randomToken(),passHash=await passwordHash(password,salt),id=crypto.randomUUID();
   try{await env.DB.prepare('INSERT INTO users (id,username,password_hash,password_salt,created_at) VALUES (?,?,?,?,?)').bind(id,username,passHash,salt,new Date().toISOString()).run()}catch{return json({error:'این نام کاربری قبلاً ثبت شده است'},409)}
   const token=randomToken(),expires=new Date(Date.now()+30*86400000).toISOString();
   await env.DB.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').bind(await hashText(token),id,expires).run();
   return json({user:{id,username}},201,{'set-cookie':cookie('flash_session',token,30*86400)});
  }
  if(path==='/api/auth/login'&&method==='POST'){
   if(!sameOrigin(request))return json({error:'درخواست نامعتبر است'},403);
   let body;try{body=await request.json()}catch{return json({error:'اطلاعات نامعتبر است'},400)}
   const username=String(body.username||'').trim().toLowerCase(),password=String(body.password||'');
   const user=await env.DB.prepare('SELECT id,username,password_hash,password_salt FROM users WHERE username=?').bind(username).first();
   if(!user||password.length>128||await passwordHash(password,user.password_salt)!==user.password_hash)return json({error:'نام کاربری یا رمز عبور اشتباه است'},401);
   const token=randomToken(),expires=new Date(Date.now()+30*86400000).toISOString();
   await env.DB.prepare('INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)').bind(await hashText(token),user.id,expires).run();
   return json({user:{id:user.id,username:user.username}},200,{'set-cookie':cookie('flash_session',token,30*86400)});
  }
  if(path==='/api/auth/me'&&method==='GET'){const user=await currentUser(request,env);return user?json({user}):json({error:'وارد نشده‌اید'},401)}
  if(path==='/api/auth/logout'&&method==='POST'){
   if(!sameOrigin(request))return json({error:'درخواست نامعتبر است'},403);
   const raw=request.headers.get('Cookie')||'',token=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith('flash_session='))?.slice(14);
   if(token)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await hashText(token)).run();
   return json({ok:true},200,{'set-cookie':clearCookie()});
  }
  if(path==='/api/files'&&method==='GET'){
   const user=await currentUser(request,env);if(!user)return json({error:'ابتدا وارد شوید'},401);
   const {results}=await env.DB.prepare('SELECT files.id,files.name,files.size,files.content_type AS type,files.created_at,files.owner_id,users.username AS owner FROM files JOIN users ON users.id=files.owner_id ORDER BY files.created_at DESC LIMIT 500').all();
   return json({files:results});
  }
  if(path==='/api/files'&&method==='POST'){
   const user=await currentUser(request,env);if(!user)return json({error:'ابتدا وارد شوید'},401);
   if(!sameOrigin(request))return json({error:'درخواست نامعتبر است'},403);
   if(!storageConfig(env))return json({error:'کلید امن فضای ذخیره‌سازی هنوز در Cloudflare تنظیم نشده است'},503);
   let form;try{form=await request.formData()}catch{return json({error:'فرم آپلود نامعتبر است'},400)}
   const file=form.get('file');if(!file||typeof file.arrayBuffer!=='function')return json({error:'فایلی انتخاب نشده است'},400);
   if(file.size<1||file.size>50*1024*1024)return json({error:'حجم فایل باید حداکثر ۵۰ مگابایت باشد'},413);
   const id=crypto.randomUUID(),key='uploads/'+id,name=safeName(file.name),type=(file.type||'application/octet-stream').slice(0,120),cfg=storageConfig(env);
   let uploaded;try{uploaded=await storageRequest(env,'/object/'+encodeURIComponent(cfg.bucket)+'/'+key,{method:'POST',headers:{'Content-Type':type,'x-upsert':'false'},body:await file.arrayBuffer()})}catch{return json({error:'ارتباط با فضای ذخیره‌سازی برقرار نشد'},502)}
   if(!uploaded.ok)return json({error:'ذخیره فایل ناموفق بود ('+uploaded.status+')'},502);
   try{await env.DB.prepare('INSERT INTO files (id,owner_id,name,object_key,size,content_type,created_at) VALUES (?,?,?,?,?,?,?)').bind(id,user.id,name,key,file.size,type,new Date().toISOString()).run()}catch{await storageRequest(env,'/object/'+encodeURIComponent(cfg.bucket)+'/'+key,{method:'DELETE'}).catch(()=>{});return json({error:'ثبت اطلاعات فایل ناموفق بود'},500)}
   return json({ok:true,id},201);
  }
  if(path.startsWith('/api/files/')&&(method==='GET'||method==='DELETE')){
   const user=await currentUser(request,env);if(!user)return json({error:'ابتدا وارد شوید'},401);
   const id=decodeURIComponent(path.slice('/api/files/'.length));if(!id||id.includes('/'))return json({error:'فایل پیدا نشد'},404);
   const file=await env.DB.prepare('SELECT * FROM files WHERE id=?').bind(id).first();if(!file)return json({error:'فایل پیدا نشد'},404);
   const cfg=storageConfig(env);if(!cfg)return json({error:'کلید امن فضای ذخیره‌سازی هنوز در Cloudflare تنظیم نشده است'},503);
   const objectPath=file.object_key.split('/').map(encodeURIComponent).join('/');
   if(method==='GET'){
    let obj;try{obj=await storageRequest(env,'/object/authenticated/'+encodeURIComponent(cfg.bucket)+'/'+objectPath,{method:'GET'})}catch{return json({error:'دریافت فایل ناموفق بود'},502)}
    if(!obj.ok)return json({error:obj.status===404?'محتوای فایل در دسترس نیست':'دریافت فایل ناموفق بود'},obj.status===404?404:502);
    const preview=url.searchParams.get('preview')==='1',disposition=preview&&inlineTypes.includes(file.content_type)?'inline':'attachment';
    return new Response(obj.body,{headers:{'content-type':file.content_type||'application/octet-stream','content-length':String(file.size),'content-disposition':disposition+"; filename*=UTF-8''"+encodeURIComponent(file.name),'cache-control':'private, no-store','x-content-type-options':'nosniff'}});
   }
   if(!sameOrigin(request))return json({error:'درخواست نامعتبر است'},403);
   if(file.owner_id!==user.id)return json({error:'فقط بارگذار فایل می‌تواند آن را حذف کند'},403);
   let removed;try{removed=await storageRequest(env,'/object/'+encodeURIComponent(cfg.bucket)+'/'+objectPath,{method:'DELETE'})}catch{return json({error:'حذف فایل ناموفق بود'},502)}
   if(!removed.ok)return json({error:'حذف فایل ناموفق بود'},502);
   await env.DB.prepare('DELETE FROM files WHERE id=?').bind(id).run();return json({ok:true});
  }
  return json({error:'مسیر پیدا نشد'},404);
 }
 if(env.ASSETS)return env.ASSETS.fetch(request);
 return new Response('Not found',{status:404});
}
export default {async fetch(request,env){try{return await handle(request,env)}catch(e){return json({error:'خطای داخلی سرور'},500)}}};
