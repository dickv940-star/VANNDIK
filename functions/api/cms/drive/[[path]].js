const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const uid=()=>crypto.randomUUID();
const b64=bytes=>btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64=value=>Uint8Array.from(atob(value),c=>c.charCodeAt(0));
const DRIVE_EMAIL='dickv940@gmail.com';
const REDIRECT_URI='https://vanndik.pages.dev/api/cms/drive/callback';
const COOKIE='vanndik_cms_session';

async function adminFor(request,env){
  const raw=(request.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1);
  if(!raw)return null;
  let token;try{token=decodeURIComponent(raw);}catch{return null;}
  const digest=b64(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(token)));
  return env.CMS_DB.prepare('SELECT a.id,a.email,a.role FROM cms_sessions s JOIN cms_admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>? AND a.active=1').bind(digest,new Date().toISOString()).first();
}
async function keyFor(env){
  if(!env.GOOGLE_DRIVE_TOKEN_KEY)throw new Error('Secret GOOGLE_DRIVE_TOKEN_KEY belum diatur di Cloudflare.');
  const raw=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(env.GOOGLE_DRIVE_TOKEN_KEY));
  return crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
}
async function encrypt(value,env){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},await keyFor(env),new TextEncoder().encode(value));
  const all=new Uint8Array(iv.length+cipher.byteLength);all.set(iv);all.set(new Uint8Array(cipher),iv.length);return b64(all);
}
async function decrypt(value,env){
  const all=unb64(value),iv=all.slice(0,12),cipher=all.slice(12);
  const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv},await keyFor(env),cipher);
  return new TextDecoder().decode(plain);
}
async function ensureDriveTables(env){
  await env.CMS_DB.prepare("CREATE TABLE IF NOT EXISTS cms_drive_connection (id TEXT PRIMARY KEY, google_email TEXT NOT NULL, refresh_token_enc TEXT NOT NULL, folder_id TEXT NOT NULL, connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  await env.CMS_DB.prepare("CREATE TABLE IF NOT EXISTS cms_drive_oauth_states (state TEXT PRIMARY KEY, expires_at TEXT NOT NULL)").run();
}
async function connection(env){
  return env.CMS_DB.prepare("SELECT * FROM cms_drive_connection WHERE id='primary'").first();
}
async function accessToken(env,conn){
  if(!env.GOOGLE_DRIVE_CLIENT_ID||!env.GOOGLE_DRIVE_CLIENT_SECRET)throw new Error('OAuth Google Drive belum dikonfigurasi di Cloudflare.');
  if(!conn?.refresh_token_enc)throw new Error('Google Drive belum terhubung.');
  const refreshToken=await decrypt(conn.refresh_token_enc,env);
  const form=new URLSearchParams({client_id:env.GOOGLE_DRIVE_CLIENT_ID,client_secret:env.GOOGLE_DRIVE_CLIENT_SECRET,refresh_token:refreshToken,grant_type:'refresh_token'});
  const response=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:form});
  const data=await response.json();
  if(!response.ok||!data.access_token)throw new Error('Gagal memperbarui akses Google Drive. Hubungkan ulang akun Google.');
  return data.access_token;
}
async function driveRequest(token,path,options={}){
  const response=await fetch('https://www.googleapis.com/drive/v3'+path,{...options,headers:{Authorization:'Bearer '+token,...(options.headers||{})}});
  const data=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(data.error?.message||'Google Drive API gagal ('+response.status+').');
  return data;
}
async function ensureFolder(token){
  const q="name='VANNDIK Media' and mimeType='application/vnd.google-apps.folder' and trashed=false";
  const found=await driveRequest(token,'/files?q='+encodeURIComponent(q)+'&pageSize=10&fields=files(id,name)');
  if(found.files?.length)return found.files[0].id;
  const made=await driveRequest(token,'/files?fields=id,name',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:'VANNDIK Media',mimeType:'application/vnd.google-apps.folder'})});
  return made.id;
}
function redirect(url,query){
  const target=new URL('/admin/',url.origin);
  for(const [k,v] of Object.entries(query))target.searchParams.set(k,v);
  return Response.redirect(target.toString(),302);
}

export async function onRequest({request,env}){
  const url=new URL(request.url),path=url.pathname.replace(/^\/api\/cms\/drive\/?/,'').replace(/\/$/,'');
  const method=request.method.toUpperCase();
  try{
    if(!env.CMS_DB)return json({error:'Database CMS belum terhubung.'},503);
    if(method!=='GET'){
      const origin=request.headers.get('origin');
      if(origin&&origin!==url.origin)return json({error:'Origin tidak diizinkan.'},403);
    }

    // OAuth callback uses a one-time, expiring state value; no admin session is needed on this redirect.
    if(path==='callback'&&method==='GET'){
      const code=url.searchParams.get('code'),state=url.searchParams.get('state');
      if(url.searchParams.get('error'))return redirect(url,{drive_error:'consent_denied'});
      if(!code||!state)return redirect(url,{drive_error:'invalid_callback'});
      await ensureDriveTables(env);
      const stateRow=await env.CMS_DB.prepare('SELECT state FROM cms_drive_oauth_states WHERE state=? AND expires_at>?').bind(state,new Date().toISOString()).first();
      if(!stateRow)return redirect(url,{drive_error:'state_expired'});
      await env.CMS_DB.prepare('DELETE FROM cms_drive_oauth_states WHERE state=?').bind(state).run();
      if(!env.GOOGLE_DRIVE_CLIENT_ID||!env.GOOGLE_DRIVE_CLIENT_SECRET)return redirect(url,{drive_error:'oauth_not_configured'});
      const tokenForm=new URLSearchParams({code,client_id:env.GOOGLE_DRIVE_CLIENT_ID,client_secret:env.GOOGLE_DRIVE_CLIENT_SECRET,redirect_uri:REDIRECT_URI,grant_type:'authorization_code'});
      const tokenResponse=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:tokenForm});
      const tokenData=await tokenResponse.json();
      if(!tokenResponse.ok||!tokenData.access_token)return redirect(url,{drive_error:'token_exchange_failed'});
      const who=await fetch('https://openidconnect.googleapis.com/v1/userinfo',{headers:{Authorization:'Bearer '+tokenData.access_token}});
      const identity=await who.json();
      if(!who.ok||String(identity.email||'').toLowerCase()!==DRIVE_EMAIL)return redirect(url,{drive_error:'wrong_google_account'});
      const old=await connection(env);
      const refresh=tokenData.refresh_token||(old?.refresh_token_enc?await decrypt(old.refresh_token_enc,env):null);
      if(!refresh)return redirect(url,{drive_error:'refresh_token_missing'});
      const folderId=await ensureFolder(tokenData.access_token);
      const encrypted=await encrypt(refresh,env);
      await env.CMS_DB.prepare("INSERT INTO cms_drive_connection(id,google_email,refresh_token_enc,folder_id,connected_at) VALUES('primary',?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(id) DO UPDATE SET google_email=excluded.google_email,refresh_token_enc=excluded.refresh_token_enc,folder_id=excluded.folder_id,connected_at=CURRENT_TIMESTAMP").bind(DRIVE_EMAIL,encrypted,folderId).run();
      return redirect(url,{drive:'connected'});
    }

    const admin=await adminFor(request,env);
    if(!admin)return json({error:'Silakan login sebagai admin VANNDIK.'},401);
    await ensureDriveTables(env);

    if(path==='connect'&&method==='GET'){
      if(!env.GOOGLE_DRIVE_CLIENT_ID||!env.GOOGLE_DRIVE_CLIENT_SECRET||!env.GOOGLE_DRIVE_TOKEN_KEY)return json({error:'Konfigurasi belum lengkap. Atur GOOGLE_DRIVE_CLIENT_ID, GOOGLE_DRIVE_CLIENT_SECRET, dan GOOGLE_DRIVE_TOKEN_KEY di Cloudflare Pages.'},503);
      const state=[...crypto.getRandomValues(new Uint8Array(32))].map(x=>x.toString(16).padStart(2,'0')).join('');
      await env.CMS_DB.prepare('DELETE FROM cms_drive_oauth_states WHERE expires_at<?').bind(new Date().toISOString()).run();
      await env.CMS_DB.prepare('INSERT INTO cms_drive_oauth_states(state,expires_at) VALUES(?,?)').bind(state,new Date(Date.now()+10*60*1000).toISOString()).run();
      const auth=new URL('https://accounts.google.com/o/oauth2/v2/auth');
      auth.searchParams.set('client_id',env.GOOGLE_DRIVE_CLIENT_ID);
      auth.searchParams.set('redirect_uri',REDIRECT_URI);
      auth.searchParams.set('response_type','code');
      auth.searchParams.set('scope','openid email https://www.googleapis.com/auth/drive.file');
      auth.searchParams.set('access_type','offline');
      auth.searchParams.set('prompt','consent');
      auth.searchParams.set('include_granted_scopes','true');
      auth.searchParams.set('state',state);
      return Response.redirect(auth.toString(),302);
    }
    if(path==='status'&&method==='GET'){
      const conn=await connection(env);
      return json({configured:!!(env.GOOGLE_DRIVE_CLIENT_ID&&env.GOOGLE_DRIVE_CLIENT_SECRET&&env.GOOGLE_DRIVE_TOKEN_KEY),connected:!!conn?.refresh_token_enc,email:conn?.google_email||null,folderName:'VANNDIK Media'});
    }
    if(path==='files'&&method==='GET'){
      const conn=await connection(env);if(!conn?.refresh_token_enc)return json({error:'Hubungkan Google Drive terlebih dahulu.'},409);
      const token=await accessToken(env,conn);
      const q="'"+conn.folder_id+"' in parents and trashed=false";
      const data=await driveRequest(token,'/files?q='+encodeURIComponent(q)+'&pageSize=100&orderBy=createdTime%20desc&fields=files(id,name,mimeType,size,createdTime,webViewLink)');
      const items=(data.files||[]).filter(f=>String(f.mimeType||'').startsWith('image/')).map(f=>({...f,imageUrl:'https://drive.google.com/uc?export=view&id='+f.id}));
      return json({items});
    }

    if(path==='import-image'&&method==='POST'){
      const data=await request.json(),raw=String(data.url||'');
      let imageUrl;try{imageUrl=new URL(raw)}catch{return json({error:'URL foto produk tidak valid.'},400);}
      const allowedHosts=['down-id.img.susercontent.com','down-id.img.shopee.com','cf.shopee.co.id','cf.shopee.com'];
      if(imageUrl.protocol!=='https:'||!allowedHosts.includes(imageUrl.hostname.toLowerCase()))return json({error:'Sumber foto belum didukung. Hanya CDN gambar Shopee Indonesia yang diizinkan.'},400);
      const conn=await connection(env);if(!conn?.refresh_token_enc)return json({error:'Hubungkan Google Drive terlebih dahulu.'},409);
      const response=await fetch(imageUrl.href,{method:'GET',redirect:'error',signal:AbortSignal.timeout(10000),headers:{accept:'image/avif,image/webp,image/png,image/jpeg,*/*;q=0.5','user-agent':'Mozilla/5.0 (compatible; VANNDIKMediaImporter/1.0)'}});
      if(!response.ok)return json({error:'Foto produk tidak dapat diambil dari CDN marketplace (HTTP '+response.status+').'},502);
      const mime=(response.headers.get('content-type')||'').split(';')[0].trim().toLowerCase();
      const extensions={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif','image/avif':'avif'};
      if(!extensions[mime])return json({error:'CDN tidak mengembalikan format gambar yang didukung.'},415);
      if(Number(response.headers.get('content-length')||0)>8*1024*1024)return json({error:'Foto produk melebihi batas 8 MB.'},413);
      const reader=response.body?.getReader();if(!reader)return json({error:'Data foto tidak dapat dibaca.'},502);
      const chunks=[];let total=0;
      try{while(true){const part=await reader.read();if(part.done)break;total+=part.value.byteLength;if(total>8*1024*1024){await reader.cancel();return json({error:'Foto produk melebihi batas 8 MB.'},413);}chunks.push(part.value);}}
      catch{try{await reader.cancel()}catch{}return json({error:'Pengunduhan foto produk terputus.'},502);}
      if(!total)return json({error:'Foto produk kosong.'},422);
      const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
      const token=await accessToken(env,conn);
      const base=String(data.fileName||'produk-vanndik').normalize('NFKD').replace(/[^a-zA-Z0-9_-]+/g,'-').slice(0,70)||'produk-vanndik';
      const metadata={name:base+'.'+extensions[mime],mimeType:mime,parents:[conn.folder_id]};
      const boundary='vanndik_'+uid().replaceAll('-','');
      const head='--'+boundary+'\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'+JSON.stringify(metadata)+'\r\n--'+boundary+'\r\nContent-Type: '+mime+'\r\n\r\n';
      const tail='\r\n--'+boundary+'--';
      const payload=new Blob([head,bytes,tail],{type:'multipart/related; boundary='+boundary});
      const uploadedResponse=await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,mimeType,size',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'multipart/related; boundary='+boundary},body:payload});
      const uploaded=await uploadedResponse.json().catch(()=>({}));
      if(!uploadedResponse.ok||!uploaded.id)throw new Error(uploaded.error?.message||'Gagal menyimpan foto produk ke Google Drive.');
      try{await driveRequest(token,'/files/'+uploaded.id+'/permissions?fields=id',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({type:'anyone',role:'reader'})});}
      catch(error){await fetch('https://www.googleapis.com/drive/v3/files/'+uploaded.id,{method:'DELETE',headers:{Authorization:'Bearer '+token}}).catch(()=>{});throw new Error('Foto tersimpan tetapi akses tampil publik gagal. Periksa kebijakan berbagi Google Drive.');}
      await env.CMS_DB.prepare("INSERT INTO cms_audit_logs(id,admin_id,action,target_type,target_id,details) VALUES(?,?,?,?,?,?)").bind(uid(),admin.id,'media.marketplace_imported','media',uploaded.id,JSON.stringify({name:uploaded.name,size:uploaded.size,sourceHost:imageUrl.hostname})).run();
      return json({ok:true,item:{...uploaded,imageUrl:'https://drive.google.com/uc?export=view&id='+uploaded.id}},201);
    }

    if(path==='upload'&&method==='POST'){
      const conn=await connection(env);if(!conn?.refresh_token_enc)return json({error:'Hubungkan Google Drive terlebih dahulu.'},409);
      const form=await request.formData(),file=form.get('file');
      if(!file||typeof file.arrayBuffer!=='function')return json({error:'Pilih file gambar terlebih dahulu.'},400);
      const allowed=['image/jpeg','image/png','image/webp','image/gif','image/avif'];
      if(!allowed.includes(file.type))return json({error:'Format didukung: JPG, PNG, WEBP, GIF, AVIF. SVG tidak diizinkan.'},415);
      if(file.size<1||file.size>8*1024*1024)return json({error:'Ukuran gambar maksimal 8 MB.'},413);
      const token=await accessToken(env,conn);
      const cleanName=String(file.name||'image').normalize('NFKD').replace(/[^a-zA-Z0-9._-]+/g,'-').slice(-120)||'image';
      const metadata={name:Date.now()+'-'+cleanName,mimeType:file.type,parents:[conn.folder_id]};
      const boundary='vanndik_'+uid().replaceAll('-','');
      const head='--'+boundary+'\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n'+JSON.stringify(metadata)+'\r\n--'+boundary+'\r\nContent-Type: '+file.type+'\r\n\r\n';
      const tail='\r\n--'+boundary+'--';
      const bytes=await file.arrayBuffer();
      const payload=new Blob([head,new Uint8Array(bytes),tail],{type:'multipart/related; boundary='+boundary});
      const response=await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,name,mimeType,size,createdTime,webViewLink',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'multipart/related; boundary='+boundary},body:payload});
      const uploaded=await response.json().catch(()=>({}));
      if(!response.ok||!uploaded.id)throw new Error(uploaded.error?.message||'Upload ke Google Drive gagal.');
      try{
        await driveRequest(token,'/files/'+uploaded.id+'/permissions?fields=id',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({type:'anyone',role:'reader'})});
      }catch(error){
        await fetch('https://www.googleapis.com/drive/v3/files/'+uploaded.id,{method:'DELETE',headers:{Authorization:'Bearer '+token}}).catch(()=>{});
        throw new Error('File terunggah tetapi izin tampil publik gagal. Periksa kebijakan berbagi Google Drive.');
      }
      await env.CMS_DB.prepare("INSERT INTO cms_audit_logs(id,admin_id,action,target_type,target_id,details) VALUES(?,?,?,?,?,?)").bind(uid(),admin.id,'media.uploaded','media',uploaded.id,JSON.stringify({name:uploaded.name,size:uploaded.size})).run();
      return json({ok:true,item:{...uploaded,imageUrl:'https://drive.google.com/uc?export=view&id='+uploaded.id}},201);
    }
    if(path.startsWith('files/')&&method==='DELETE'){
      const id=path.slice(6);
      if(!/^[a-zA-Z0-9_-]{10,}$/.test(id))return json({error:'ID file tidak valid.'},400);
      const used=await env.CMS_DB.prepare('SELECT COUNT(*) total FROM cms_content WHERE image_url LIKE ?').bind('%'+id+'%').first();
      if(Number(used?.total||0)>0)return json({error:'Gambar masih digunakan oleh konten. Ganti URL gambar pada konten terlebih dahulu.'},409);
      const conn=await connection(env);if(!conn?.refresh_token_enc)return json({error:'Google Drive belum terhubung.'},409);
      const token=await accessToken(env,conn);
      const response=await fetch('https://www.googleapis.com/drive/v3/files/'+encodeURIComponent(id),{method:'DELETE',headers:{Authorization:'Bearer '+token}});
      if(!response.ok&&response.status!==404)return json({error:'Gagal menghapus file dari Google Drive.'},502);
      await env.CMS_DB.prepare("INSERT INTO cms_audit_logs(id,admin_id,action,target_type,target_id,details) VALUES(?,?,?,?,?,?)").bind(uid(),admin.id,'media.deleted','media',id,'{}').run();
      return json({ok:true});
    }
    return json({error:'Endpoint Google Drive tidak ditemukan.'},404);
  }catch(error){
    console.error('VANNDIK Google Drive',error);
    return json({error:error?.message||'Integrasi Google Drive mengalami kesalahan.'},500);
  }
}
