const COOKIE = 'vanndik_cms_session';
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const sha = async value => btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))));
const uid = () => crypto.randomUUID();
const cookie = req => (req.headers.get('cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1) || '';
async function requireAdmin(request, env) {
  const token = cookie(request);
  if (!token) return null;
  let decoded = token;
  try { decoded = decodeURIComponent(token); } catch {}
  const hash = await sha(decoded);
  return env.CMS_DB.prepare("SELECT a.id,a.email,a.display_name,a.role FROM cms_sessions s JOIN cms_admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>? AND a.active=1")
    .bind(hash, new Date().toISOString()).first();
}
async function ensureSchema(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS affiliate_click_events (
    id TEXT PRIMARY KEY, event_type TEXT NOT NULL DEFAULT 'affiliate_click',
    product_name TEXT NOT NULL DEFAULT '', product_id TEXT NOT NULL DEFAULT '',
    page_path TEXT NOT NULL DEFAULT '', destination_host TEXT NOT NULL DEFAULT '',
    marketplace TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '',
    referrer_host TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_affiliate_click_created ON affiliate_click_events(created_at)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_affiliate_click_product ON affiliate_click_events(product_id, created_at)').run();
}
export async function onRequest({ request, env }) {
  if (!env.CMS_DB) return json({ error: 'Database VANNDIK belum terhubung.' }, 503);
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/cms\/growth\/?/, '').replace(/\/$/, '');
  try {
    await ensureSchema(env.CMS_DB);
    if (path === 'stats' && request.method === 'GET') {
      const admin = await requireAdmin(request, env);
      if (!admin) return json({ error: 'Silakan login ke CMS terlebih dahulu.' }, 401);
      const range = Math.min(90, Math.max(1, Number(url.searchParams.get('days') || 30)));
      const since = new Date(Date.now() - range * 86400000).toISOString();
      const [total, products, countries, days, marketplaces] = await Promise.all([
        env.CMS_DB.prepare('SELECT COUNT(*) total FROM affiliate_click_events WHERE created_at>=?').bind(since).first(),
        env.CMS_DB.prepare('SELECT product_name,product_id,COUNT(*) clicks FROM affiliate_click_events WHERE created_at>=? GROUP BY product_id,product_name ORDER BY clicks DESC LIMIT 8').bind(since).all(),
        env.CMS_DB.prepare("SELECT COALESCE(NULLIF(country,''),'Unknown') country,COUNT(*) clicks FROM affiliate_click_events WHERE created_at>=? GROUP BY country ORDER BY clicks DESC LIMIT 8").bind(since).all(),
        env.CMS_DB.prepare("SELECT substr(created_at,1,10) day,COUNT(*) clicks FROM affiliate_click_events WHERE created_at>=? GROUP BY substr(created_at,1,10) ORDER BY day").bind(since).all(),
        env.CMS_DB.prepare("SELECT COALESCE(NULLIF(marketplace,''),'Other') marketplace,COUNT(*) clicks FROM affiliate_click_events WHERE created_at>=? GROUP BY marketplace ORDER BY clicks DESC LIMIT 8").bind(since).all()
      ]);
      return json({ range, totalClicks: Number(total?.total || 0), products: products.results || [], countries: countries.results || [], days: days.results || [], marketplaces: marketplaces.results || [] });
    }
    if (path === 'events' && request.method === 'GET') {
      const admin = await requireAdmin(request, env);
      if (!admin) return json({ error: 'Silakan login ke CMS terlebih dahulu.' }, 401);
      const rows = await env.CMS_DB.prepare('SELECT product_name,product_id,page_path,destination_host,marketplace,country,created_at FROM affiliate_click_events ORDER BY created_at DESC LIMIT 100').all();
      return json({ items: rows.results || [] });
    }
    return json({ error: 'Endpoint tidak ditemukan.' }, 404);
  } catch (error) {
    console.error('VANNDIK Growth API', error);
    return json({ error: 'Terjadi kesalahan saat memuat data Growth.' }, 500);
  }
}
