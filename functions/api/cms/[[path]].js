import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';

const COOKIE = 'vanndik_cms_session';
const TTL = 43200;
const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
const uid = () => crypto.randomUUID();
const to64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const from64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const random = (n = 32) => [...crypto.getRandomValues(new Uint8Array(n))].map(x => x.toString(16).padStart(2, '0')).join('');
const sha = async value => to64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));
const pbkdf = async (password, salt) => {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return to64(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: from64(salt), iterations: 310000, hash: 'SHA-256' }, key, 256));
};
const equal = (a, b) => {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0; for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i); return diff === 0;
};
const body = async req => { if (Number(req.headers.get('content-length') || 0) > 1024 * 1024) throw new Error('Permintaan terlalu besar.'); return req.json(); };
const cookie = req => (req.headers.get('cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1) || '';
const setCookie = token => COOKIE + '=' + encodeURIComponent(token) + '; HttpOnly; Secure; SameSite=Lax; Path=/api/cms; Max-Age=' + TTL;
const clearCookie = COOKIE + '=; HttpOnly; Secure; SameSite=Lax; Path=/api/cms; Max-Age=0';
const originCheck = req => { const origin = req.headers.get('origin'); if (origin && origin !== new URL(req.url).origin) throw new Error('Origin tidak diizinkan.'); };
const audit = (env, admin, action, target = '', id = '', details = {}) => env.CMS_DB.prepare('INSERT INTO cms_audit_logs(id,admin_id,action,target_type,target_id,details) VALUES(?,?,?,?,?,?)').bind(uid(), admin?.id || null, action, target, id, JSON.stringify(details)).run();
const session = async (admin, env) => {
  const token = random(32);
  await env.CMS_DB.prepare('INSERT INTO cms_sessions(id,admin_id,token_hash,expires_at) VALUES(?,?,?,?)').bind(uid(), admin.id, await sha(token), new Date(Date.now() + TTL * 1000).toISOString()).run();
  return token;
};
const currentAdmin = async (req, env) => {
  const token = cookie(req); if (!token) return null;
  return await env.CMS_DB.prepare('SELECT a.id,a.email,a.display_name,a.role FROM cms_sessions s JOIN cms_admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>? AND a.active=1').bind(await sha(decodeURIComponent(token)), new Date().toISOString()).first();
};
const saveChallenge = async (env, challenge, email, purpose) => {
  await env.CMS_DB.prepare('DELETE FROM cms_challenges WHERE expires_at<?').bind(new Date().toISOString()).run();
  await env.CMS_DB.prepare('INSERT INTO cms_challenges(id,challenge,email,purpose,expires_at) VALUES(?,?,?,?,?)').bind(uid(), challenge, email, purpose, new Date(Date.now() + 300000).toISOString()).run();
};
const getChallenge = (env, email, purpose) => env.CMS_DB.prepare('SELECT id,challenge FROM cms_challenges WHERE email=? AND purpose=? AND expires_at>? ORDER BY rowid DESC LIMIT 1').bind(email, purpose, new Date().toISOString()).first();
const clean = data => ({
  type: String(data.type || ''), title: String(data.title || '').trim().slice(0,180),
  slug: String(data.slug || data.title || '').normalize('NFKD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,90),
  excerpt: String(data.excerpt || '').slice(0,600), body: String(data.body || '').slice(0,100000),
  image_url: String(data.image_url || '').slice(0,2000), category: String(data.category || '').slice(0,80),
  tags: JSON.stringify(Array.isArray(data.tags) ? data.tags.slice(0,20).map(x => String(x).slice(0,40)) : []),
  status: ['draft','published','scheduled','archived'].includes(data.status) ? data.status : 'draft',
  affiliate_url: String(data.affiliate_url || '').slice(0,2000), target_url: String(data.target_url || '').slice(0,2000),
  price: String(data.price || '').slice(0,80), featured: data.featured ? 1 : 0,
  sort_order: Math.max(0, Math.min(99999, Number(data.sort_order) || 0)), published_at: data.published_at ? String(data.published_at).slice(0,40) : null
});
const types = ['article','news','product','game','app'];
const safeUrl = v => !v || /^https?:\/\//i.test(v) || v.startsWith('/');

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/cms\/?/, '').replace(/\/$/, '');
  const method = request.method.toUpperCase();
  try {
    if (!env.CMS_DB) return json({ error: 'Database CMS belum terhubung.' }, 503);
    if (method !== 'GET') originCheck(request);

    if (path === 'setup' && method === 'GET') {
      const row = await env.CMS_DB.prepare('SELECT COUNT(*) total FROM cms_admins').first();
      return json({ setupRequired: Number(row.total) === 0 });
    }
    if (path === 'setup' && method === 'POST') {
      const data = await body(request);
      const count = await env.CMS_DB.prepare('SELECT COUNT(*) total FROM cms_admins').first();
      if (Number(count.total) > 0) return json({ error: 'Pendaftaran admin utama telah ditutup.' }, 409);
      if (!env.CMS_SETUP_TOKEN || !equal(String(data.setupToken || ''), env.CMS_SETUP_TOKEN)) return json({ error: 'Kode aktivasi tidak valid.' }, 403);
      const email = String(data.email || '').trim().toLowerCase(), password = String(data.password || '');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: 'Email tidak valid.' }, 400);
      if (password.length < 12 || password.length > 128) return json({ error: 'Password minimal 12 karakter.' }, 400);
      const salt = to64(crypto.getRandomValues(new Uint8Array(16)));
      const admin = { id: uid(), email, display_name: String(data.displayName || 'Administrator').trim().slice(0,80), role: 'owner' };
      await env.CMS_DB.prepare('INSERT INTO cms_admins(id,email,display_name,password_hash,password_salt,role) VALUES(?,?,?,?,?,?)').bind(admin.id,email,admin.display_name,await pbkdf(password,salt),salt,'owner').run();
      const token = await session(admin, env); await audit(env,admin,'admin.initialized','admin',admin.id);
      return json({ ok:true, admin },201,{ 'set-cookie':setCookie(token) });
    }
    if (path === 'login' && method === 'POST') {
      const data = await body(request), email = String(data.email || '').trim().toLowerCase();
      const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
      const attempts = await env.CMS_DB.prepare("SELECT COUNT(*) total FROM cms_login_attempts WHERE ip=? AND created_at>datetime('now','-15 minutes')").bind(ip).first();
      if (Number(attempts?.total || 0) >= 10) return json({ error:'Terlalu banyak percobaan. Coba lagi 15 menit.' },429);
      const row = await env.CMS_DB.prepare('SELECT * FROM cms_admins WHERE email=? COLLATE NOCASE AND active=1').bind(email).first();
      const check = row ? await pbkdf(String(data.password || ''),row.password_salt) : '';
      if (!row || !equal(check,row.password_hash)) {
        await env.CMS_DB.prepare('INSERT INTO cms_login_attempts(id,ip) VALUES(?,?)').bind(uid(),ip).run();
        return json({ error:'Email atau password tidak cocok.' },401);
      }
      await env.CMS_DB.prepare('DELETE FROM cms_login_attempts WHERE ip=?').bind(ip).run();
      const admin = { id:row.id,email:row.email,display_name:row.display_name,role:row.role };
      const token = await session(admin,env); await audit(env,admin,'auth.password_login');
      return json({ ok:true,admin },200,{ 'set-cookie':setCookie(token) });
    }
    if (path === 'passkey/login/options' && method === 'POST') {
      const data = await body(request), email = String(data.email || '').trim().toLowerCase();
      const admin = await env.CMS_DB.prepare('SELECT id,email FROM cms_admins WHERE email=? COLLATE NOCASE AND active=1').bind(email).first();
      if (!admin) return json({ error:'Akun atau passkey tidak ditemukan.' },404);
      const rows = await env.CMS_DB.prepare('SELECT credential_id,transports FROM cms_passkeys WHERE admin_id=?').bind(admin.id).all();
      if (!rows.results?.length) return json({ error:'Passkey belum didaftarkan. Login dengan password terlebih dahulu.' },404);
      const options = await generateAuthenticationOptions({ rpID:url.hostname, allowCredentials:rows.results.map(x=>({id:x.credential_id,transports:JSON.parse(x.transports||'[]')})), userVerification:'required' });
      await saveChallenge(env,options.challenge,email,'passkey-login'); return json(options);
    }
    if (path === 'passkey/login/verify' && method === 'POST') {
      const data = await body(request), email = String(data.email || '').trim().toLowerCase();
      const admin = await env.CMS_DB.prepare('SELECT * FROM cms_admins WHERE email=? COLLATE NOCASE AND active=1').bind(email).first();
      const challenge = await getChallenge(env,email,'passkey-login');
      if (!admin || !challenge) return json({error:'Sesi verifikasi kedaluwarsa. Ulangi login.'},400);
      const key = await env.CMS_DB.prepare('SELECT * FROM cms_passkeys WHERE admin_id=? AND credential_id=?').bind(admin.id,String(data.response?.id||'')).first();
      if (!key) return json({error:'Passkey tidak dikenali.'},401);
      const result = await verifyAuthenticationResponse({response:data.response,expectedChallenge:challenge.challenge,expectedOrigin:url.origin,expectedRPID:url.hostname,credential:{id:key.credential_id,publicKey:from64(key.public_key),counter:Number(key.counter),transports:JSON.parse(key.transports||'[]')}});
      await env.CMS_DB.prepare('DELETE FROM cms_challenges WHERE id=?').bind(challenge.id).run();
      if (!result.verified) return json({error:'Verifikasi passkey gagal.'},401);
      await env.CMS_DB.prepare('UPDATE cms_passkeys SET counter=?,last_used_at=CURRENT_TIMESTAMP WHERE id=?').bind(result.authenticationInfo.newCounter,key.id).run();
      const safe = {id:admin.id,email:admin.email,display_name:admin.display_name,role:admin.role};
      const token = await session(safe,env); await audit(env,safe,'auth.passkey_login');
      return json({ok:true,admin:safe},200,{'set-cookie':setCookie(token)});
    }

    if (path === 'logout' && method === 'POST') {
      const token = cookie(request); if(token) await env.CMS_DB.prepare('DELETE FROM cms_sessions WHERE token_hash=?').bind(await sha(decodeURIComponent(token))).run();
      return json({ok:true},200,{'set-cookie':clearCookie});
    }
    const admin = await currentAdmin(request,env);
    if (path === 'me' && method === 'GET') return admin ? json({authenticated:true,admin}) : json({authenticated:false},401);
    if (!admin) return json({error:'Silakan login terlebih dahulu.'},401);

    if (path === 'stats' && method === 'GET') {
      const rows = await env.CMS_DB.prepare('SELECT type,status,COUNT(*) total FROM cms_content GROUP BY type,status').all();
      const activity = await env.CMS_DB.prepare('SELECT action,created_at FROM cms_audit_logs ORDER BY created_at DESC LIMIT 8').all();
      const stats = {article:0,news:0,product:0,game:0,app:0,published:0,draft:0};
      for (const row of rows.results||[]) { stats[row.type]+=Number(row.total); stats[row.status]=(stats[row.status]||0)+Number(row.total); }
      return json({stats,activity:activity.results||[]});
    }
    if (path === 'content' && method === 'GET') {
      const type=url.searchParams.get('type')||'', q='%'+(url.searchParams.get('q')||'')+'%';
      const rows=await env.CMS_DB.prepare("SELECT * FROM cms_content WHERE (?='' OR type=?) AND (title LIKE ? OR category LIKE ?) ORDER BY featured DESC,sort_order ASC,updated_at DESC LIMIT 300").bind(type,type,q,q).all();
      return json({items:rows.results||[]});
    }
    if (path === 'content' && method === 'POST') {
      const item=clean(await body(request));
      if(!types.includes(item.type)||!item.title||!item.slug) return json({error:'Jenis dan judul wajib diisi.'},400);
      if(!safeUrl(item.image_url)||!safeUrl(item.affiliate_url)||!safeUrl(item.target_url)) return json({error:'URL harus menggunakan http atau https.'},400);
      const id=uid();
      try { await env.CMS_DB.prepare('INSERT INTO cms_content(id,type,title,slug,excerpt,body,image_url,category,tags,status,affiliate_url,target_url,price,featured,sort_order,published_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,item.type,item.title,item.slug,item.excerpt,item.body,item.image_url,item.category,item.tags,item.status,item.affiliate_url,item.target_url,item.price,item.featured,item.sort_order,item.published_at).run(); }
      catch { return json({error:'Slug sudah digunakan atau data tidak valid.'},409); }
      await audit(env,admin,'content.created',item.type,id,{title:item.title,status:item.status}); return json({ok:true,id},201);
    }
    if (path.startsWith('content/') && method === 'PUT') {
      const id=path.split('/')[1], item=clean(await body(request));
      if(!types.includes(item.type)||!item.title||!item.slug) return json({error:'Jenis dan judul wajib diisi.'},400);
      if(!safeUrl(item.image_url)||!safeUrl(item.affiliate_url)||!safeUrl(item.target_url)) return json({error:'URL harus menggunakan http atau https.'},400);
      try { const result=await env.CMS_DB.prepare('UPDATE cms_content SET type=?,title=?,slug=?,excerpt=?,body=?,image_url=?,category=?,tags=?,status=?,affiliate_url=?,target_url=?,price=?,featured=?,sort_order=?,published_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(item.type,item.title,item.slug,item.excerpt,item.body,item.image_url,item.category,item.tags,item.status,item.affiliate_url,item.target_url,item.price,item.featured,item.sort_order,item.published_at,id).run(); if(!result.meta.changes)return json({error:'Konten tidak ditemukan.'},404); }
      catch { return json({error:'Slug sudah digunakan atau data tidak valid.'},409); }
      await audit(env,admin,'content.updated',item.type,id,{title:item.title,status:item.status}); return json({ok:true});
    }
    if (path.startsWith('content/') && method === 'DELETE') {
      const id=path.split('/')[1]; await env.CMS_DB.prepare('DELETE FROM cms_content WHERE id=?').bind(id).run(); await audit(env,admin,'content.deleted','content',id); return json({ok:true});
    }
    if (path === 'settings' && method === 'GET') {
      const rows=await env.CMS_DB.prepare('SELECT key,value FROM cms_site_settings ORDER BY key').all();
      return json({settings:Object.fromEntries((rows.results||[]).map(x=>[x.key,x.value]))});
    }
    if (path === 'settings' && method === 'PUT') {
      const data=await body(request);
      for(const [key,value] of Object.entries(data.settings||{}).slice(0,100)){
        if(!/^(theme\.|site\.)[a-z0-9._-]{1,80}$/i.test(key))continue;
        const val=typeof value==='string'?value:JSON.stringify(value);
        await env.CMS_DB.prepare('INSERT INTO cms_site_settings(key,value,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP').bind(key,String(val).slice(0,20000)).run();
      }
      await audit(env,admin,'settings.updated','settings','',{keys:Object.keys(data.settings||{})}); return json({ok:true});
    }
    if (path === 'passkey/register/options' && method === 'POST') {
      const rows=await env.CMS_DB.prepare('SELECT credential_id,transports FROM cms_passkeys WHERE admin_id=?').bind(admin.id).all();
      const options=await generateRegistrationOptions({rpName:'VANNDIK CMS',rpID:url.hostname,userID:new TextEncoder().encode(admin.id),userName:admin.email,userDisplayName:admin.display_name,attestationType:'none',excludeCredentials:(rows.results||[]).map(x=>({id:x.credential_id,transports:JSON.parse(x.transports||'[]')})),authenticatorSelection:{residentKey:'required',userVerification:'required',authenticatorAttachment:'platform'},supportedAlgorithmIDs:[-7,-257]});
      await saveChallenge(env,options.challenge,admin.email,'passkey-register'); return json(options);
    }
    if (path === 'passkey/register/verify' && method === 'POST') {
      const data=await body(request), challenge=await getChallenge(env,admin.email,'passkey-register');
      if(!challenge)return json({error:'Sesi pendaftaran kedaluwarsa.'},400);
      const result=await verifyRegistrationResponse({response:data.response,expectedChallenge:challenge.challenge,expectedOrigin:url.origin,expectedRPID:url.hostname});
      await env.CMS_DB.prepare('DELETE FROM cms_challenges WHERE id=?').bind(challenge.id).run();
      if(!result.verified||!result.registrationInfo)return json({error:'Pendaftaran passkey gagal.'},400);
      const credential=result.registrationInfo.credential;
      await env.CMS_DB.prepare('INSERT INTO cms_passkeys(id,admin_id,credential_id,public_key,counter,transports,device_name) VALUES(?,?,?,?,?,?,?)').bind(uid(),admin.id,credential.id,to64(credential.publicKey),credential.counter,JSON.stringify(credential.transports||[]),String(data.deviceName||'Perangkat saya').slice(0,80)).run();
      await audit(env,admin,'passkey.registered'); return json({ok:true});
    }
    if (path === 'passkeys' && method === 'GET') {
      const rows=await env.CMS_DB.prepare('SELECT id,device_name,created_at,last_used_at FROM cms_passkeys WHERE admin_id=? ORDER BY created_at DESC').bind(admin.id).all(); return json({items:rows.results||[]});
    }
    if (path.startsWith('passkeys/') && method === 'DELETE') {
      const id=path.split('/')[1], count=await env.CMS_DB.prepare('SELECT COUNT(*) total FROM cms_passkeys WHERE admin_id=?').bind(admin.id).first();
      if(Number(count.total)<=1)return json({error:'Simpan minimal satu passkey agar tidak terkunci.'},400);
      await env.CMS_DB.prepare('DELETE FROM cms_passkeys WHERE id=? AND admin_id=?').bind(id,admin.id).run(); await audit(env,admin,'passkey.deleted','passkey',id); return json({ok:true});
    }
    return json({error:'Endpoint tidak ditemukan.'},404);
  } catch (error) {
    console.error('VANNDIK CMS API',error);
    return json({error:error?.message||'Terjadi kesalahan server.'},500);
  }
}
