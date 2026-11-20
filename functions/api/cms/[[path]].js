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
  return to64(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: from64(salt), iterations: 100000, hash: 'SHA-256' }, key, 256));
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
const seoClean = value => String(value || '').replace(/<[^>]*>/g, ' ').replace(/[#*_>~]/g, ' ').replace(/\s+/g, ' ').trim();
function makeSeo(data) {
  const title = seoClean(data.title).slice(0, 180);
  let description = seoClean(data.seo_description || data.excerpt || data.body);
  if (description.length < 70) description = seoClean(title + '. ' + (data.body || data.category || 'Informasi pilihan dari VANNDIK.'));
  if (description.length < 70) description = title + ' — Temukan informasi, detail, dan rekomendasi selengkapnya di VANNDIK.';
  if (description.length > 160) description = description.slice(0, 157).replace(/\s+\S*$/, '') + '…';
  const stopWords = new Set('yang dan atau untuk dari pada dengan dalam ini itu ke di oleh akan bisa juga lebih sangat agar saat jika karena sebuah para the and for with from into this that your you are was were have has had not but all can will should their they them our'.split(' '));
  const frequency = new Map();
  for (const word of (title + ' ' + (data.category || '') + ' ' + seoClean(data.body).slice(0, 3000)).toLowerCase().split(/[^a-z0-9]+/)) if (word.length > 2 && !stopWords.has(word)) frequency.set(word, (frequency.get(word) || 0) + 1);
  const keywords = [...frequency].sort((a,b) => b[1] - a[1]).slice(0, 8).map(([word]) => word);
  const seoTitle = seoClean(data.seo_title || title).slice(0, 70);
  const checks = { title: seoTitle.length >= 30 && seoTitle.length <= 60, description: description.length >= 70 && description.length <= 160, keywordInTitle: keywords.some(k => seoTitle.toLowerCase().includes(k)), keywordInDescription: keywords.some(k => description.toLowerCase().includes(k)), body: seoClean(data.body).split(' ').filter(Boolean).length >= 300, image: !!data.image_url, category: !!data.category };
  const score = Math.round(Object.values(checks).filter(Boolean).length / Object.keys(checks).length * 100);
  return { seo_title: seoTitle, seo_description: description, seo_keywords: (data.seo_keywords || keywords.join(', ')), canonical_url: String(data.canonical_url || '').slice(0, 500), og_image: String(data.og_image || data.image_url || '').slice(0, 2000), seo_score: score, seo_checks: JSON.stringify(checks) };
}
async function ensureSeoTable(env) { await env.CMS_DB.prepare("CREATE TABLE IF NOT EXISTS cms_content_seo (content_id TEXT PRIMARY KEY, seo_title TEXT NOT NULL DEFAULT '', seo_description TEXT NOT NULL DEFAULT '', seo_keywords TEXT NOT NULL DEFAULT '', canonical_url TEXT NOT NULL DEFAULT '', og_image TEXT NOT NULL DEFAULT '', seo_score INTEGER NOT NULL DEFAULT 0, seo_checks TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run(); }
async function ensureProductAiTable(env) {
  await env.CMS_DB.prepare("CREATE TABLE IF NOT EXISTS cms_product_ai_work (product_id TEXT PRIMARY KEY, status TEXT NOT NULL DEFAULT 'pending', result_json TEXT NOT NULL DEFAULT '{}', model TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  await env.CMS_DB.prepare("CREATE TABLE IF NOT EXISTS cms_ai_daily_usage (day TEXT PRIMARY KEY, jobs INTEGER NOT NULL DEFAULT 0)").run();
}
async function saveSeo(env, id, seo) { await env.CMS_DB.prepare("INSERT INTO cms_content_seo(content_id,seo_title,seo_description,seo_keywords,canonical_url,og_image,seo_score,seo_checks,updated_at) VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(content_id) DO UPDATE SET seo_title=excluded.seo_title,seo_description=excluded.seo_description,seo_keywords=excluded.seo_keywords,canonical_url=excluded.canonical_url,og_image=excluded.og_image,seo_score=excluded.seo_score,seo_checks=excluded.seo_checks,updated_at=CURRENT_TIMESTAMP").bind(id,seo.seo_title,seo.seo_description,seo.seo_keywords,seo.canonical_url,seo.og_image,seo.seo_score,seo.seo_checks).run(); }

const MARKETPLACE_HOSTS=['shopee.co.id','shopee.com','shope.ee','shp.ee','tiktok.com','vt.tiktok.com','vm.tiktok.com','tokopedia.com','tokopedia.link','lazada.co.id','lazada.com','blibli.com','amazon.com','amazon.co.uk','amazon.co.jp','amazon.de','amzn.to','aliexpress.com','aliexpress.us','temu.com','ebay.com','ebay.to','walmart.com','jd.com','taobao.com','tmall.com','zalora.co.id','zalora.com','bit.ly','tinyurl.com'];
const hostAllowed=host=>MARKETPLACE_HOSTS.some(domain=>host===domain||host.endsWith('.'+domain));
function validateProductUrl(value){
  let url;try{url=new URL(String(value||'').trim());}catch{throw new Error('Format link tidak valid. Tempel URL lengkap yang diawali https://.');}
  if(!['https:','http:'].includes(url.protocol)||url.username||url.password||!hostAllowed(url.hostname.toLowerCase()))throw new Error('Domain belum didukung. Gunakan link marketplace seperti Shopee, TikTok Shop, Tokopedia, Lazada, atau Amazon.');
  if(url.port&&!['80','443'].includes(url.port))throw new Error('Port URL tidak diizinkan.');
  url.hash='';return url;
}
async function fetchMarketplaceHtml(startUrl){
  let current=startUrl;
  for(let hop=0;hop<=5;hop++){
    validateProductUrl(current.href);
    // Keep the same deadline active while streaming the response body, not only until headers arrive.
    const signal=AbortSignal.timeout(12000);let response;
    try{response=await fetch(current.href,{method:'GET',redirect:'manual',signal,headers:{'accept':'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5','accept-language':'id-ID,id;q=0.9,en;q=0.8','user-agent':'Mozilla/5.0 (compatible; VANNDIKProductPreview/1.0; +https://vanndik.pages.dev/)'}});}
    catch(error){if(error?.name==='AbortError'||error?.name==='TimeoutError')throw new Error('Halaman marketplace terlalu lama merespons. Coba lagi beberapa saat.');throw new Error('Halaman marketplace tidak dapat diakses otomatis. Marketplace mungkin membatasi pembacaan bot.');}
    if([301,302,303,307,308].includes(response.status)){const location=response.headers.get('location');if(!location||hop===5)throw new Error('Tautan pengalihan terlalu panjang atau tidak lengkap.');current=new URL(location,current);continue;}
    if(!response.ok)throw new Error('Marketplace menolak pembacaan halaman (HTTP '+response.status+'). Periksa link secara manual atau coba lagi nanti.');
    const contentType=response.headers.get('content-type')||'';
    if(!/text\/html|application\/xhtml\+xml/i.test(contentType))throw new Error('Link tidak mengarah ke halaman produk HTML yang dapat dibaca.');
    if(Number(response.headers.get('content-length')||0)>1200000)throw new Error('Halaman terlalu besar untuk dianalisis secara gratis dan aman.');
    const reader=response.body?.getReader();if(!reader)throw new Error('Isi halaman tidak dapat dibaca.');
    const chunks=[];let total=0;
    try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>1200000){await reader.cancel();throw new Error('Halaman terlalu besar untuk dianalisis secara gratis dan aman.');}chunks.push(value);}}
    catch(error){try{await reader.cancel();}catch{}if(signal.aborted)throw new Error('Halaman marketplace terlalu lama mengirim data. Coba lagi beberapa saat.');throw error;}
    const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
    return {html:new TextDecoder('utf-8').decode(bytes),finalUrl:current};
  }
  throw new Error('Tautan tidak berhasil diarahkan ke halaman produk.');
}
const decodeEntities=value=>String(value||'').replace(/&amp;/gi,'&').replace(/&quot;/gi,'"').replace(/&#39;|&apos;/gi,"'").replace(/&lt;/gi,'<').replace(/&gt;/gi,'>').replace(/&#(\d+);/g,(_,n)=>String.fromCodePoint(Math.min(0x10ffff,Number(n)))).replace(/&#x([\da-f]+);/gi,(_,n)=>String.fromCodePoint(Math.min(0x10ffff,parseInt(n,16)))).replace(/\\u0026/gi,'&').replace(/\\u003c/gi,'<').replace(/\\u003e/gi,'>');
const stripText=value=>decodeEntities(String(value||'').replace(/<[^>]*>/g,' ').replace(/\s+/g,' ')).trim();
function htmlAttributes(tag){const attrs={};for(const match of tag.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g))attrs[match[1].toLowerCase()]=decodeEntities(match[2]??match[3]??match[4]??'');return attrs;}
function readProductMetadata(html,pageUrl){
  const meta={};for(const match of html.matchAll(/<meta\b[^>]*>/gi)){const a=htmlAttributes(match[0]),key=(a.property||a.name||a.itemprop||'').toLowerCase();if(key)meta[key]=a.content||a.value||'';}
  const links=[...html.matchAll(/<link\b[^>]*>/gi)].map(x=>htmlAttributes(x[0]));
  const canonicalLink=links.find(x=>(x.rel||'').toLowerCase().split(/\s+/).includes('canonical'))?.href||'';
  const titleTag=html.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1]||'';
  const products=[];
  const visit=value=>{if(!value)return;if(Array.isArray(value)){value.forEach(visit);return;}if(typeof value!=='object')return;const type=value['@type'];if((Array.isArray(type)?type:[type]).some(x=>String(x||'').toLowerCase().split(/[\/#]/).pop()==='product'))products.push(value);if(value['@graph'])visit(value['@graph']);for(const [key,child] of Object.entries(value))if(key!=='@graph'&&child&&typeof child==='object')visit(child);};
  for(const match of html.matchAll(/<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)){try{visit(JSON.parse(match[1].trim().replace(/^<!--|-->$/g,'')));}catch{}}
  const product=products[0]||{},offers=Array.isArray(product.offers)?product.offers[0]:product.offers||{};
  const imageValue=Array.isArray(product.image)?product.image[0]:(typeof product.image==='object'?product.image.url:product.image);
  const title=stripText(product.name||meta['og:title']||meta['twitter:title']||titleTag).replace(/\s*[|–—-]\s*(Shopee|Tokopedia|TikTok Shop|Lazada|Amazon).*$/i,'').slice(0,180);
  const description=stripText(product.description||meta['og:description']||meta.description||meta['twitter:description']).slice(0,600);
  const rawImage=imageValue||meta['og:image']||meta['og:image:url']||meta['twitter:image']||'';let image='';try{image=rawImage?new URL(rawImage,pageUrl).href:'';}catch{}
  const rawPrice=offers.price||offers.lowPrice||product.price||meta['product:price:amount']||meta['og:price:amount']||'',currency=offers.priceCurrency||meta['product:price:currency']||meta['og:price:currency']||'';
  let price='';if(rawPrice!==''){const text=String(rawPrice).trim(),numeric=Number(currency.toUpperCase()==='IDR'?text.replace(/[^\d-]/g,''):text.replace(/[^\d.,-]/g,'').replace(/,(?=\d{3}(?:\D|$))/g,'').replace(',','.'));if(Number.isFinite(numeric)){try{price=currency.toUpperCase()==='IDR'?new Intl.NumberFormat('id-ID',{style:'currency',currency:'IDR',maximumFractionDigits:0}).format(numeric):(currency?currency.toUpperCase()+' '+numeric:String(rawPrice));}catch{price=(currency?currency.toUpperCase()+' ':'')+numeric;}}}
  const category=stripText(product.category||meta['product:category']||meta['article:section']||'').slice(0,80),brandValue=product.brand&&typeof product.brand==='object'?product.brand.name:product.brand;
  return {title,description,image,price,category,brand:stripText(brandValue||'').slice(0,80),hasProductSchema:products.length>0};
}
async function analyzeAffiliateProduct(env,admin,rawUrl){
  const original=validateProductUrl(rawUrl),duplicate=await env.CMS_DB.prepare("SELECT id,title FROM cms_content WHERE type='product' AND affiliate_url=? LIMIT 1").bind(original.href).first();
  if(duplicate)throw new Error('Link ini sudah ada di CMS sebagai "'+duplicate.title+'". Periksa antrean produk yang sudah ada.');
  const page=await fetchMarketplaceHtml(original),meta=readProductMetadata(page.html,page.finalUrl);
  if(!meta.title||meta.title.length<3)throw new Error('Nama produk tidak berhasil dibaca dari halaman tujuan. Marketplace mungkin memblokir metadata. Tidak ada data yang disimpan.');
  const id=uid(),baseSlug=meta.title.normalize('NFKD').replace(/[\u0300-\u036f]/g,'').toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,72)||'produk';
  let slug=baseSlug,suffix=1;while(await env.CMS_DB.prepare('SELECT id FROM cms_content WHERE slug=? LIMIT 1').bind(slug).first())slug=(baseSlug.slice(0,78)+'-'+suffix++).slice(0,90);
  const excerpt=meta.description||'Deskripsi produk tidak tersedia pada metadata halaman sumber. Periksa halaman marketplace sebelum menampilkan produk.';
  const bodyText=[meta.description,meta.brand?'Merek: '+meta.brand:'',meta.category?'Kategori: '+meta.category:'',meta.price?'Harga yang terbaca: '+meta.price:'','Sumber: '+page.finalUrl.href].filter(Boolean).join('\n\n');
  const tags=JSON.stringify(['metadata-extracted','marketplace-page-read',page.finalUrl.hostname]);
  const data=clean({type:'product',title:meta.title,slug,excerpt,body:bodyText,image_url:meta.image,category:meta.category,tags:['metadata-extracted','marketplace-page-read',page.finalUrl.hostname],status:'draft',affiliate_url:original.href,target_url:page.finalUrl.href,price:meta.price});
  await env.CMS_DB.prepare('INSERT INTO cms_content(id,type,title,slug,excerpt,body,image_url,category,tags,status,affiliate_url,target_url,price,featured,sort_order,published_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,data.type,data.title,data.slug,data.excerpt,data.body,data.image_url,data.category,data.tags,data.status,data.affiliate_url,data.target_url,data.price,data.featured,data.sort_order,null).run();
  const seo=makeSeo({...data,seo_description:meta.description,canonical_url:new URL('/produk/'+encodeURIComponent(slug)+'/','https://vanndik.pages.dev').href,og_image:meta.image});
  await saveSeo(env,id,seo);await audit(env,admin,'affiliate.product.analyzed','product',id,{sourceHost:page.finalUrl.hostname,hasProductSchema:meta.hasProductSchema,hasImage:!!meta.image,hasPrice:!!meta.price});
  return {id,type:'product',title:meta.title,slug,excerpt,image_url:meta.image,category:meta.category,price:meta.price,affiliate_url:original.href,target_url:page.finalUrl.href,status:'draft',tags,seo_score:seo.seo_score,metadata:{descriptionFound:!!meta.description,imageFound:!!meta.image,priceFound:!!meta.price,productSchemaFound:meta.hasProductSchema,sourceHost:page.finalUrl.hostname}};
}
const safeUrl = v => !v || /^https?:\/\//i.test(v) || v.startsWith('/');

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/cms\/?/, '').replace(/\/$/, '');
  const method = request.method.toUpperCase();
  try {
    if (!env.CMS_DB) return json({ error: 'Database CMS belum terhubung.' }, 503);
    if (method !== 'GET') originCheck(request);
    await ensureSeoTable(env);
    await ensureProductAiTable(env);

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

    if (path === 'product/analyze' && method === 'POST') {
      const data=await body(request);
      if(!data.url||String(data.url).length>2000)return json({error:'Masukkan satu link affiliate yang valid (maksimal 2.000 karakter).'},400);
      try{const item=await analyzeAffiliateProduct(env,admin,String(data.url));return json({ok:true,item},201);}
      catch(error){
        let sourceUrl=String(data.url).slice(0,2000);
        try{const parsed=new URL(sourceUrl);if(!['http:','https:'].includes(parsed.protocol))sourceUrl='';}catch{sourceUrl='';}
        try{await audit(env,admin,'affiliate.product.failed','product','',{sourceUrl,reason:String(error?.message||'Verifikasi produk gagal.').slice(0,500)});}catch{}
        return json({error:error?.message||'Analisis produk gagal.'},422);
      }
    }
    if (path === 'product/image' && method === 'POST') {
      const data=await body(request),productId=String(data.id||''),imageUrl=String(data.imageUrl||'');
      if(!productId||productId.length>80)return json({error:'ID produk tidak valid.'},400);
      let parsed;try{parsed=new URL(imageUrl)}catch{return json({error:'URL gambar tidak valid.'},400);}
      if(parsed.protocol!=='https:'||parsed.hostname!=='drive.google.com'||parsed.pathname!=='/uc'||!parsed.searchParams.get('id'))return json({error:'Gambar harus berasal dari folder media Google Drive VANNDIK.'},400);
      const item=await env.CMS_DB.prepare("SELECT * FROM cms_content WHERE id=? AND type='product'").bind(productId).first();
      if(!item)return json({error:'Produk tidak ditemukan.'},404);
      let tags=[];try{tags=JSON.parse(item.tags||'[]')}catch{}
      if(!tags.includes('metadata-extracted')||!tags.includes('marketplace-page-read'))return json({error:'Produk belum terverifikasi.'},409);
      await env.CMS_DB.prepare('UPDATE cms_content SET image_url=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(parsed.href,productId).run();
      const seo=makeSeo({...item,image_url:parsed.href,og_image:parsed.href});
      await saveSeo(env,productId,seo);
      await audit(env,admin,'affiliate.product.image_attached','product',productId,{source:'google-drive'});
      return json({ok:true,image_url:parsed.href});
    }
    if (path === 'product/ai-process' && method === 'POST') {
      const data=await body(request), productId=String(data.id||'');
      if(!productId||productId.length>80)return json({error:'ID produk tidak valid.'},400);
      const product=await env.CMS_DB.prepare("SELECT * FROM cms_content WHERE id=? AND type='product'").bind(productId).first();
      if(!product)return json({error:'Produk tidak ditemukan.'},404);
      let tags=[];try{tags=JSON.parse(product.tags||'[]')}catch{}
      let affiliate,target;
      try{affiliate=validateProductUrl(product.affiliate_url);target=validateProductUrl(product.target_url)}catch{return json({error:'Produk belum terverifikasi. Agen AI hanya berjalan pada produk dengan tautan sumber yang valid.'},409);}
      if(!tags.includes('metadata-extracted')||!tags.includes('marketplace-page-read')||!product.title)return json({error:'Produk belum lolos verifikasi sumber.'},409);
      if(!env.AI||typeof env.AI.run!=='function')return json({error:'Workers AI belum terhubung. Tambahkan binding Workers AI bernama AI pada Cloudflare Pages > Settings > Bindings, lalu deploy ulang. Tidak ada layanan berbayar yang digunakan sebagai pengganti.'},503);
      const existing=await env.CMS_DB.prepare('SELECT status,result_json FROM cms_product_ai_work WHERE product_id=?').bind(productId).first();
      if(existing?.status==='completed')return json({ok:true,alreadyCompleted:true,result:JSON.parse(existing.result_json||'{}')});
      const day=new Date().toISOString().slice(0,10);
      const quota=await env.CMS_DB.prepare("INSERT INTO cms_ai_daily_usage(day,jobs) VALUES(?,1) ON CONFLICT(day) DO UPDATE SET jobs=jobs+1 WHERE jobs<4").bind(day).run();
      if(!quota.meta?.changes)return json({error:'Batas gratis harian VANNDIK tercapai (4 proses produk per hari). Kuota lokal reset pukul 00.00 UTC; kuota Cloudflare juga dapat membatasi penggunaan lebih awal.'},429);
      const model='@cf/meta/llama-3.2-3b-instruct';
      const sourceData={
        name:product.title,description:product.excerpt||'',details:product.body||'',
        category:product.category||'',observedPrice:product.price||'',
        brand:(String(product.body||'').match(/(?:^|\n\n)Merek:\s*([^\n]+)/i)||[])[1]||'',
        marketplace:new URL(target.href).hostname,affiliateUrl:affiliate.href,productPage:target.href
      };
      const prompt=[
        'Anda adalah orkestrator tim konten affiliate VANNDIK. Buat hasil dalam Bahasa Indonesia untuk audiens internasional; jangan mengarang spesifikasi, garansi, stok, rating, review, diskon, klaim kesehatan, atau data pasar.',
        'Gunakan hanya fakta pada DATA SUMBER. Jika data tidak ada, nyatakan tidak tersedia. Perkiraan audiens/positioning harus diberi label hipotesis, bukan fakta.',
        'Peran yang harus dihasilkan dalam satu eksekusi: Product Analyst, Affiliate Strategist, Copywriter, SEO Specialist, dan Quality Control.',
        'PENTING: tidak ada pencarian web atau data tren eksternal dalam proses ini. Isi market_validation dengan "Belum diverifikasi dari sumber pasar eksternal".',
        'Kembalikan JSON valid saja dengan field: product_positioning (string), audience_hypothesis (string), key_benefits (array 3 string berdasarkan sumber), marketing_angle (string), short_copy (string maks 240 karakter), long_description (string 2-4 paragraf), seo_title (string maks 60 karakter), seo_description (string 70-160 karakter), seo_keywords (array 5-8 string), quality_notes (array string), market_validation (string).',
        'Copy harus informatif, natural, tidak berlebihan, dan tidak menambahkan fakta di luar sumber. Jangan menyebut komisi atau menjanjikan hasil.',
        'DATA SUMBER: '+JSON.stringify(sourceData)
      ].join('\n\n');
      try{
        const generated=await env.AI.run(model,{prompt,max_tokens:950,temperature:0.25,top_p:0.85});
        const raw=String(generated?.response||generated?.result?.response||'').trim();
        const jsonMatch=raw.match(/\{[\s\S]*\}/);
        if(!jsonMatch)throw new Error('Model tidak mengembalikan JSON yang dapat dibaca.');
        const parsed=JSON.parse(jsonMatch[0]);
        const shortCopy=String(parsed.short_copy||'').trim().slice(0,240);
        const longDescription=String(parsed.long_description||'').trim().slice(0,5000);
        const seoTitle=String(parsed.seo_title||product.title).trim().slice(0,60);
        const seoDescription=String(parsed.seo_description||product.excerpt||'').trim().slice(0,160);
        if(shortCopy.length<20||longDescription.length<50||seoDescription.length<40)throw new Error('Hasil AI tidak lengkap. Silakan coba lagi.');
        const result={
          product_positioning:String(parsed.product_positioning||'').slice(0,500),
          audience_hypothesis:String(parsed.audience_hypothesis||'').slice(0,500),
          key_benefits:Array.isArray(parsed.key_benefits)?parsed.key_benefits.slice(0,5).map(x=>String(x).slice(0,240)):[],
          marketing_angle:String(parsed.marketing_angle||'').slice(0,500),
          short_copy:shortCopy,long_description:longDescription,seo_title:seoTitle,seo_description:seoDescription,
          seo_keywords:Array.isArray(parsed.seo_keywords)?parsed.seo_keywords.slice(0,8).map(x=>String(x).slice(0,60)):[],
          quality_notes:Array.isArray(parsed.quality_notes)?parsed.quality_notes.slice(0,8).map(x=>String(x).slice(0,240)):[],
          market_validation:String(parsed.market_validation||'Belum diverifikasi dari sumber pasar eksternal').slice(0,240)
        };
        const bodyText=[product.body||'', 'Deskripsi produk untuk publikasi:',longDescription,result.marketing_angle?'Sudut pemasaran: '+result.marketing_angle:''].filter(Boolean).join('\n\n').slice(0,100000);
        const keywords=result.seo_keywords.join(', ');
        await env.CMS_DB.prepare('UPDATE cms_content SET excerpt=?,body=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(shortCopy,bodyText,productId).run();
        const seo=makeSeo({...product,excerpt:shortCopy,body:bodyText,seo_title:seoTitle,seo_description:seoDescription,seo_keywords:keywords,canonical_url:new URL('/produk/'+encodeURIComponent(product.slug)+'/','https://vanndik.pages.dev').href,og_image:product.image_url});
        await saveSeo(env,productId,seo);
        await env.CMS_DB.prepare("INSERT INTO cms_product_ai_work(product_id,status,result_json,model,updated_at) VALUES(?,'completed',?,?,CURRENT_TIMESTAMP) ON CONFLICT(product_id) DO UPDATE SET status='completed',result_json=excluded.result_json,model=excluded.model,updated_at=CURRENT_TIMESTAMP").bind(productId,JSON.stringify(result),model).run();
        await audit(env,admin,'affiliate.product.ai_completed','product',productId,{model,marketValidation:'not_external'});
        return json({ok:true,result,model,usage:generated?.usage||null});
      }catch(error){
        await env.CMS_DB.prepare("INSERT INTO cms_product_ai_work(product_id,status,result_json,model,updated_at) VALUES(?,'failed',?,?,CURRENT_TIMESTAMP) ON CONFLICT(product_id) DO UPDATE SET status='failed',result_json=excluded.result_json,model=excluded.model,updated_at=CURRENT_TIMESTAMP").bind(productId,JSON.stringify({error:String(error?.message||'AI gagal').slice(0,400)}),model).run();
        await audit(env,admin,'affiliate.product.ai_failed','product',productId,{model,reason:String(error?.message||'AI gagal').slice(0,400)});
        return json({error:'Proses AI gagal: '+String(error?.message||'Coba lagi nanti.').slice(0,350)},502);
      }
    }
    if (path === 'product/attempts' && method === 'GET') {
      const rows=await env.CMS_DB.prepare("SELECT id,details,created_at FROM cms_audit_logs WHERE action='affiliate.product.failed' ORDER BY created_at DESC LIMIT 20").all();
      const items=(rows.results||[]).map(row=>{let details={};try{details=JSON.parse(row.details||'{}')}catch{}return {id:row.id,sourceUrl:details.sourceUrl||'',reason:details.reason||'Perlu pemeriksaan',created_at:row.created_at};});
      return json({items});
    }
    if (path === 'backup/export' && method === 'GET') {
      const [content, settings, activity] = await Promise.all([
        env.CMS_DB.prepare('SELECT * FROM cms_content ORDER BY created_at').all(),
        env.CMS_DB.prepare('SELECT key,value,updated_at FROM cms_site_settings ORDER BY key').all(),
        env.CMS_DB.prepare('SELECT action,target_type,target_id,details,created_at FROM cms_audit_logs ORDER BY created_at DESC LIMIT 5000').all()
      ]);
      const backup = {
        product: 'VANNDIK CMS Backup',
        formatVersion: 1,
        exportedAt: new Date().toISOString(),
        note: 'Konten, pengaturan situs, dan log aktivitas. Kredensial admin, sesi, passkey, serta token Google Drive sengaja tidak disertakan.',
        data: {
          content: content.results || [],
          settings: settings.results || [],
          activity: activity.results || []
        }
      };
      await audit(env, admin, 'backup.exported', 'backup', '', {
        contentCount: backup.data.content.length,
        settingsCount: backup.data.settings.length
      });
      return json(backup, 200, { 'content-disposition': 'attachment; filename="vanndik-cms-backup.json"' });
    }
    if (path === 'stats' && method === 'GET') {
      const rows = await env.CMS_DB.prepare('SELECT type,status,COUNT(*) total FROM cms_content GROUP BY type,status').all();
      const activity = await env.CMS_DB.prepare('SELECT action,created_at FROM cms_audit_logs ORDER BY created_at DESC LIMIT 8').all();
      const stats = {article:0,news:0,product:0,game:0,app:0,published:0,draft:0};
      for (const row of rows.results||[]) { stats[row.type]+=Number(row.total); stats[row.status]=(stats[row.status]||0)+Number(row.total); }
      return json({stats,activity:activity.results||[]});
    }
    if (path === 'content' && method === 'GET') {
      const type=url.searchParams.get('type')||'', q='%'+(url.searchParams.get('q')||'')+'%';
      const rows=await env.CMS_DB.prepare("SELECT c.*,s.seo_title,s.seo_description,s.seo_keywords,s.canonical_url,s.og_image,s.seo_score,s.seo_checks,ai.status AS ai_status,ai.result_json AS ai_result_json FROM cms_content c LEFT JOIN cms_content_seo s ON s.content_id=c.id LEFT JOIN cms_product_ai_work ai ON ai.product_id=c.id WHERE (?='' OR c.type=?) AND (c.title LIKE ? OR c.category LIKE ?) ORDER BY c.featured DESC,c.sort_order ASC,c.updated_at DESC LIMIT 300").bind(type,type,q,q).all();
      return json({items:rows.results||[]});
    }
    if (path === 'content' && method === 'POST') {
      const raw=await body(request), item=clean(raw);
      if(!types.includes(item.type)||!item.title||!item.slug) return json({error:'Jenis dan judul wajib diisi.'},400);
      if(!safeUrl(item.image_url)||!safeUrl(item.affiliate_url)||!safeUrl(item.target_url)) return json({error:'URL harus menggunakan http atau https.'},400);
      const id=uid(), seo=makeSeo({...item,...raw});
      try { await env.CMS_DB.prepare('INSERT INTO cms_content(id,type,title,slug,excerpt,body,image_url,category,tags,status,affiliate_url,target_url,price,featured,sort_order,published_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,item.type,item.title,item.slug,item.excerpt,item.body,item.image_url,item.category,item.tags,item.status,item.affiliate_url,item.target_url,item.price,item.featured,item.sort_order,item.published_at).run(); }
      catch { return json({error:'Slug sudah digunakan atau data tidak valid.'},409); }
      await saveSeo(env,id,seo);
      await audit(env,admin,'content.created',item.type,id,{title:item.title,status:item.status,seoScore:seo.seo_score}); return json({ok:true,id,seo},201);
    }
    if (path.startsWith('content/') && method === 'PUT') {
      const id=path.split('/')[1], raw=await body(request), item=clean(raw), seo=makeSeo({...item,...raw});
      if(!types.includes(item.type)||!item.title||!item.slug) return json({error:'Jenis dan judul wajib diisi.'},400);
      if(!safeUrl(item.image_url)||!safeUrl(item.affiliate_url)||!safeUrl(item.target_url)) return json({error:'URL harus menggunakan http atau https.'},400);
      try { const result=await env.CMS_DB.prepare('UPDATE cms_content SET type=?,title=?,slug=?,excerpt=?,body=?,image_url=?,category=?,tags=?,status=?,affiliate_url=?,target_url=?,price=?,featured=?,sort_order=?,published_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(item.type,item.title,item.slug,item.excerpt,item.body,item.image_url,item.category,item.tags,item.status,item.affiliate_url,item.target_url,item.price,item.featured,item.sort_order,item.published_at,id).run(); if(!result.meta.changes)return json({error:'Konten tidak ditemukan.'},404); }
      catch { return json({error:'Slug sudah digunakan atau data tidak valid.'},409); }
      await saveSeo(env,id,seo);
      await audit(env,admin,'content.updated',item.type,id,{title:item.title,status:item.status,seoScore:seo.seo_score}); return json({ok:true,seo});
    }
    if (path.startsWith('content/') && method === 'DELETE') {
      const id=path.split('/')[1]; await env.CMS_DB.batch([env.CMS_DB.prepare('DELETE FROM cms_content WHERE id=?').bind(id),env.CMS_DB.prepare('DELETE FROM cms_content_seo WHERE content_id=?').bind(id)]); await audit(env,admin,'content.deleted','content',id); return json({ok:true});
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
