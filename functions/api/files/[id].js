import {response,currentUser,isSameOrigin,storageConfig,storageRequest} from '../../_lib.js';
const safeInline=['image/png','image/jpeg','image/gif','image/webp','image/avif','audio/mpeg','audio/ogg','audio/wav','audio/webm','audio/mp4','video/mp4','video/webm','video/ogg','application/pdf'];
export async function onRequestGet({request,env,params}){
 const user=await currentUser(request,env);if(!user)return response({error:'ابتدا وارد شوید'},401);
 const file=await env.DB.prepare('SELECT * FROM files WHERE id=?').bind(params.id).first();if(!file)return response({error:'فایل پیدا نشد'},404);
 let bucket;try{bucket=storageConfig(env).bucket}catch{return response({error:'اتصال فضای ذخیره‌سازی تنظیم نشده است'},503)}
 const path=file.object_key.split('/').map(encodeURIComponent).join('/');
 let obj;try{obj=await storageRequest(env,'/object/authenticated/'+encodeURIComponent(bucket)+'/'+path,{method:'GET'})}catch{return response({error:'دریافت فایل از فضای ذخیره‌سازی ناموفق بود'},502)}
 if(!obj.ok)return response({error:obj.status===404?'محتوای فایل در دسترس نیست':'دریافت فایل ناموفق بود'},obj.status===404?404:502);
 const safe=encodeURIComponent(file.name),preview=new URL(request.url).searchParams.get('preview')==='1';
 const disposition=preview&&safeInline.includes(file.content_type)?'inline':'attachment';
 return new Response(obj.body,{headers:{'content-type':file.content_type||'application/octet-stream','content-length':String(file.size),'content-disposition':disposition+"; filename*=UTF-8''"+safe,'cache-control':'private, no-store','x-content-type-options':'nosniff'}});
}
export async function onRequestDelete({request,env,params}){
 const user=await currentUser(request,env);if(!user)return response({error:'ابتدا وارد شوید'},401);
 if(!isSameOrigin(request))return response({error:'درخواست نامعتبر است'},403);
 const file=await env.DB.prepare('SELECT id,owner_id,object_key FROM files WHERE id=?').bind(params.id).first();
 if(!file)return response({error:'فایل پیدا نشد'},404);
 if(file.owner_id!==user.id)return response({error:'فقط بارگذار فایل می‌تواند آن را حذف کند'},403);
 let bucket;try{bucket=storageConfig(env).bucket}catch{return response({error:'اتصال فضای ذخیره‌سازی تنظیم نشده است'},503)}
 const path=file.object_key.split('/').map(encodeURIComponent).join('/');
 let removed;try{removed=await storageRequest(env,'/object/'+encodeURIComponent(bucket)+'/'+path,{method:'DELETE'})}catch{return response({error:'حذف فایل از فضای ذخیره‌سازی ناموفق بود'},502)}
 if(!removed.ok)return response({error:'حذف فایل از فضای ذخیره‌سازی ناموفق بود'},502);
 await env.DB.prepare('DELETE FROM files WHERE id=?').bind(params.id).run();
 return response({ok:true});
}