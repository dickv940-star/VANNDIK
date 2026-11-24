const COOKIE = 'vanndik_cms_session';
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const sha = async value => btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))));
const uid = () => crypto.randomUUID();
const audit = (env, admin, action, target = '', id = '', details = {}) => env.CMS_DB.prepare('INSERT INTO cms_audit_logs(id,admin_id,action,target_type,target_id,details) VALUES(?,?,?,?,?,?)').bind(uid(), admin?.id || null, action, target, id, JSON.stringify(details)).run();
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
  await db.prepare(`CREATE TABLE IF NOT EXISTS cms_social_metrics (
    id TEXT PRIMARY KEY, platform TEXT NOT NULL, account_label TEXT NOT NULL DEFAULT '',
    metric TEXT NOT NULL, metric_date TEXT NOT NULL, metric_value REAL NOT NULL DEFAULT 0,
    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(platform,account_label,metric,metric_date)
  )`).run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_social_metrics_date ON cms_social_metrics(platform,metric_date)').run();
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
    if (path === 'social' && request.method === 'GET') {
      const admin = await requireAdmin(request, env);
      if (!admin) return json({ error: 'Silakan login ke CMS terlebih dahulu.' }, 401);
      const range = Math.min(90, Math.max(1, Number(url.searchParams.get('days') || 30)));
      const since = new Date(Date.now() - range * 86400000).toISOString().slice(0,10);
      const [summary, latest] = await Promise.all([
        env.CMS_DB.prepare('SELECT platform,metric,SUM(metric_value) value,COUNT(*) days,MAX(metric_date) latest_date FROM cms_social_metrics WHERE metric_date>=? GROUP BY platform,metric ORDER BY platform,metric').bind(since).all(),
        env.CMS_DB.prepare('SELECT platform,MAX(imported_at) last_import FROM cms_social_metrics GROUP BY platform ORDER BY platform').all()
      ]);
      return json({ range, items: summary.results || [], lastImports: latest.results || [] });
    }
    if (path === 'import' && request.method === 'POST') {
      const admin = await requireAdmin(request, env);
      if (!admin) return json({ error: 'Silakan login ke CMS terlebih dahulu.' }, 401);
      if (Number(request.headers.get('content-length') || 0) > 2 * 1024 * 1024) return json({ error: 'File CSV terlalu besar. Pecah menjadi beberapa file.' }, 413);
      const data = await request.json();
      const rows = Array.isArray(data.rows) ? data.rows : [];
      const platforms = new Set(['youtube','instagram','facebook','tiktok','pinterest','linkedin']);
      const metrics = new Set(['views','video_views','reach','impressions','likes','comments','shares','followers','subscribers','profile_visits','clicks','watch_minutes','sessions','users','page_views']);
      if (!rows.length || rows.length > 5000) return json({ error: 'File harus berisi 1 sampai 5.000 baris data.' }, 400);
      const statements = [];
      for (const row of rows) {
        const platform = String(row.platform || '').toLowerCase().trim();
        const account = String(row.account || '').trim().slice(0,120);
        const metric = String(row.metric || '').toLowerCase().trim();
        const date = String(row.date || '').trim();
        const value = Number(row.value);
        if (!platforms.has(platform) || !metrics.has(metric) || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(value) || value < 0 || value > 1e12) {
          return json({ error: 'Format baris tidak valid. Periksa platform, metric, date (YYYY-MM-DD), dan value.' }, 400);
        }
        statements.push(env.CMS_DB.prepare(`INSERT INTO cms_social_metrics(id,platform,account_label,metric,metric_date,metric_value,imported_at)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(platform,account_label,metric,metric_date)
          DO UPDATE SET metric_value=excluded.metric_value,imported_at=excluded.imported_at`)
          .bind(uid(), platform, account, metric, date, value, new Date().toISOString()));
      }
      for (let i = 0; i < statements.length; i += 100) await env.CMS_DB.batch(statements.slice(i, i + 100));
      await audit(env, admin, 'growth.social.import', 'social-metrics', '', { rows: rows.length, platforms: [...new Set(rows.map(x => String(x.platform || '').toLowerCase()))] });
      return json({ ok: true, imported: rows.length });
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
