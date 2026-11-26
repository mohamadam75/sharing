import {response,currentUser,isSameOrigin,storageConfig,storageRequest} from '../_lib.js';
export async function onRequestGet({request,env}){const user=await currentUser(request,env);if(!user)return response({error:'ابتدا وارد شوید'},401);const {results}=await env.DB.prepare('SELECT files.id,files.name,files.size,files.content_type AS type,files.created_at,files.owner_id,users.username AS owner FROM files JOIN users ON users.id=files.owner_id ORDER BY files.created_at DESC LIMIT 500').all();return response({files:results})}
export async function onRequestPost({request,env}){
 const user=await currentUser(request,env);if(!user)return response({error:'ابتدا وارد شوید'},401);
 if(!isSameOrigin(request))return response({error:'درخواست نامعتبر است'},403);
 let form;try{form=await request.formData()}catch{return response({error:'فرم آپلود نامعتبر است'},400)}
 const file=form.get('file');if(!file||typeof file.arrayBuffer!=='function')return response({error:'فایلی انتخاب نشده است'},400);
 if(file.size<1||file.size>50*1024*1024)return response({error:'حجم فایل باید حداکثر ۵۰ مگابایت باشد'},413);
 const id=crypto.randomUUID(),key='uploads/'+id;
 const name=String(file.name||'file').replace(/[\\\\/\\x00-\\x1f]/g,'_').slice(0,240);
 const type=(file.type||'application/octet-stream').slice(0,120);
 let bucket;try{bucket=storageConfig(env).bucket}catch{return response({error:'اتصال فضای ذخیره‌سازی هنوز تنظیم نشده است'},503)}
 let uploaded;
 try{
  uploaded=await storageRequest(env,'/object/'+encodeURIComponent(bucket)+'/'+key,{method:'POST',headers:{'Content-Type':type,'x-upsert':'false','cache-control':'3600'},body:await file.arrayBuffer()});
 }catch{return response({error:'ارتباط با فضای ذخیره‌سازی برقرار نشد'},502)}
 if(!uploaded.ok)return response({error:'ذخیره فایل ناموفق بود ('+uploaded.status+')'},502);
 try{
  await env.DB.prepare('INSERT INTO files (id,owner_id,name,object_key,size,content_type,created_at) VALUES (?,?,?,?,?,?,?)').bind(id,user.id,name,key,file.size,type,new Date().toISOString()).run();
 }catch(e){
  await storageRequest(env,'/object/'+encodeURIComponent(bucket)+'/'+key,{method:'DELETE'}).catch(()=>{});
  return response({error:'ثبت اطلاعات فایل ناموفق بود'},500);
 }
 return response({ok:true,id},201);
}