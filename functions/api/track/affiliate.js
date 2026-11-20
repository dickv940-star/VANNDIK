const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const clean = (value, max = 180) => String(value || '').trim().slice(0, max);
const host = value => { try { return new URL(value).hostname.toLowerCase().slice(0,180); } catch { return ''; } };
export async function onRequest({ request, env }) {
  if (request.method !== 'POST') return json({ error: 'Method tidak diizinkan.' }, 405);
  if (!env.CMS_DB) return json({ error: 'Tracking belum tersedia.' }, 503);
  const origin = request.headers.get('origin');
  if (origin && origin !== new URL(request.url).origin) return json({ error: 'Origin tidak diizinkan.' }, 403);
  try {
    const data = await request.json();
    const destination = clean(data.destination, 2000);
    if (!/^https?:\/\//i.test(destination)) return json({ error: 'Tujuan tautan tidak valid.' }, 400);
    await env.CMS_DB.prepare(`CREATE TABLE IF NOT EXISTS affiliate_click_events (
      id TEXT PRIMARY KEY, event_type TEXT NOT NULL DEFAULT 'affiliate_click',
      product_name TEXT NOT NULL DEFAULT '', product_id TEXT NOT NULL DEFAULT '',
      page_path TEXT NOT NULL DEFAULT '', destination_host TEXT NOT NULL DEFAULT '',
      marketplace TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '',
      referrer_host TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`).run();
    await env.CMS_DB.prepare('CREATE INDEX IF NOT EXISTS idx_affiliate_click_created ON affiliate_click_events(created_at)').run();
    await env.CMS_DB.prepare('INSERT INTO affiliate_click_events(id,event_type,product_name,product_id,page_path,destination_host,marketplace,country,referrer_host,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
      .bind(crypto.randomUUID(), 'affiliate_click', clean(data.productName), clean(data.productId,100), clean(data.pagePath,300), host(destination), clean(data.marketplace,60), clean(request.headers.get('cf-ipcountry'),8), host(request.headers.get('referer') || ''), new Date().toISOString()).run();
    return json({ ok: true }, 202);
  } catch (error) {
    console.error('VANNDIK affiliate tracking', error);
    return json({ error: 'Klik belum dapat dicatat.' }, 500);
  }
}
