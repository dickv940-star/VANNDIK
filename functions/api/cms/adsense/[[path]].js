const COOKIE = 'vanndik_cms_session';
const OWNER_EMAIL = 'dickv940@gmail.com';
const REDIRECT_URI = 'https://vanndik.pages.dev/api/cms/google-growth/callback';
const clientId = env => env.GOOGLE_GROWTH_CLIENT_ID || env.GOOGLE_DRIVE_CLIENT_ID;
const clientSecret = env => env.GOOGLE_GROWTH_CLIENT_SECRET || env.GOOGLE_DRIVE_CLIENT_SECRET;
const tokenKey = env => env.GOOGLE_GROWTH_TOKEN_KEY || env.GOOGLE_DRIVE_TOKEN_KEY;
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const sha = async value => b64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));

async function ensureConnectionTable(env) {
  await env.CMS_DB.prepare(`CREATE TABLE IF NOT EXISTS cms_google_growth_connection (
    id TEXT PRIMARY KEY, google_email TEXT NOT NULL, refresh_token_enc TEXT NOT NULL,
    connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).run();
}
async function adminFor(request, env) {
  const raw = (request.headers.get('cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1);
  if (!raw) return null;
  let token; try { token = decodeURIComponent(raw); } catch { return null; }
  return env.CMS_DB.prepare('SELECT a.id,a.email,a.role FROM cms_sessions s JOIN cms_admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>? AND a.active=1')
    .bind(await sha(token), new Date().toISOString()).first();
}
async function decrypt(value, env) {
  if (!tokenKey(env)) throw new Error('Secret enkripsi Google Drive/Growth belum tersedia di Cloudflare.');
  const raw = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(tokenKey(env)));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
  const data = unb64(value);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, key, data.slice(12));
  return new TextDecoder().decode(plain);
}
async function accessToken(env) {
  const conn = await env.CMS_DB.prepare("SELECT google_email,refresh_token_enc FROM cms_google_growth_connection WHERE id='primary'").first();
  if (!conn?.refresh_token_enc) throw new Error('Akun Google belum terhubung. Hubungkan akun melalui Google Growth terlebih dahulu.');
  if (String(conn.google_email).toLowerCase() !== OWNER_EMAIL) throw new Error('Koneksi Google tersimpan bukan akun pemilik VANNDIK.');
  if (!clientId(env) || !clientSecret(env)) throw new Error('OAuth Google belum dikonfigurasi di Cloudflare.');
  const refresh = await decrypt(conn.refresh_token_enc, env);
  const form = new URLSearchParams({ client_id: clientId(env), client_secret: clientSecret(env), refresh_token: refresh, grant_type: 'refresh_token' });
  const response = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) throw new Error(data.error?.error_description || 'Token Google gagal diperbarui. Hubungkan ulang akun Google dan setujui izin AdSense.');
  return data.access_token;
}
async function googleGet(url, token) {
  const response = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data.error?.message || 'Google API gagal (' + response.status + ').';
    if (response.status === 403) throw new Error(message + ' Pastikan AdSense Management API aktif dan izin adsense.readonly sudah disetujui.');
    throw new Error(message);
  }
  return data;
}
function dateParts(date) { return { year: date.getUTCFullYear(), month: date.getUTCMonth() + 1, day: date.getUTCDate() }; }
function addDays(date, amount) { const d = new Date(date); d.setUTCDate(d.getUTCDate() + amount); return d; }

async function ensureCommissionTable(env) {
  await env.CMS_DB.prepare(`CREATE TABLE IF NOT EXISTS affiliate_commissions (
    id TEXT PRIMARY KEY, platform TEXT NOT NULL, order_id TEXT NOT NULL, order_date TEXT NOT NULL,
    product_name TEXT NOT NULL DEFAULT '', commission_amount REAL NOT NULL, currency TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', source TEXT NOT NULL DEFAULT 'csv_import',
    imported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(platform, order_id)
  )`).run();
}
async function affiliateSummary(env) {
  await ensureCommissionTable(env);
  const [groups, clicks] = await Promise.all([
    env.CMS_DB.prepare("SELECT platform,currency,status,COUNT(*) AS orders,SUM(commission_amount) AS commission FROM affiliate_commissions GROUP BY platform,currency,status ORDER BY platform,currency,status").all(),
    env.CMS_DB.prepare("SELECT marketplace,COUNT(*) AS clicks FROM affiliate_click_events GROUP BY marketplace ORDER BY clicks DESC").all().catch(() => ({ results: [] }))
  ]);
  const totals = {};
  for (const row of groups.results || []) {
    if (row.status === 'cancelled') continue;
    const key = row.currency;
    totals[key] = (totals[key] || 0) + Number(row.commission || 0);
  }
  return { groups: groups.results || [], totalsByCurrency: totals, clicksByMarketplace: clicks.results || [], totalClicks: (clicks.results || []).reduce((n,x) => n + Number(x.clicks || 0), 0) };
}
export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/cms\/adsense\/?/, '').replace(/\/$/, '');
  try {
    if (!env.CMS_DB) return json({ error: 'Database CMS belum terhubung.' }, 503);
    await ensureConnectionTable(env);
    if (request.method !== 'GET') {
      const origin = request.headers.get('origin');
      if (origin && origin !== url.origin) return json({ error: 'Origin tidak diizinkan.' }, 403);
    }
    const admin = await adminFor(request, env);
    if (!admin) return json({ error: 'Silakan login sebagai admin VANNDIK.' }, 401);
    if (path === 'status') {
      const conn = await env.CMS_DB.prepare("SELECT google_email,connected_at FROM cms_google_growth_connection WHERE id='primary'").first();
      return json({ configured: !!(clientId(env) && clientSecret(env) && tokenKey(env)), connected: !!conn, email: conn?.google_email || null, connectedAt: conn?.connected_at || null, adsenseScopeAdded: true });
    }
    if (path === 'affiliate-summary') {
      return json(await affiliateSummary(env));
    }
    if (path === 'affiliate-import' && request.method === 'POST') {
      const body = await request.json();
      const rows = Array.isArray(body.rows) ? body.rows : [];
      if (!rows.length || rows.length > 200) return json({ error: 'Unggah 1–200 baris komisi per proses.' }, 400);
      await ensureCommissionTable(env);
      const allowedPlatforms = new Set(['shopee','tiktok','tokopedia','lazada','amazon','other']);
      const allowedStatuses = new Set(['pending','approved','paid','cancelled']);
      let imported = 0, rejected = 0;
      for (const row of rows) {
        const platform = String(row.platform || '').trim().toLowerCase();
        const orderId = String(row.order_id || row.orderId || '').trim().slice(0,120);
        const date = String(row.order_date || row.orderDate || '').trim();
        const product = String(row.product_name || row.productName || '').trim().slice(0,240);
        const amount = Number(row.commission);
        const currency = String(row.currency || 'IDR').trim().toUpperCase();
        const status = String(row.status || 'pending').trim().toLowerCase();
        if (!allowedPlatforms.has(platform) || !orderId || !/^\\d{4}-\\d{2}-\\d{2}$/.test(date) || !Number.isFinite(amount) || amount < 0 || !/^[A-Z]{3}$/.test(currency) || !allowedStatuses.has(status)) { rejected++; continue; }
        await env.CMS_DB.prepare(`INSERT INTO affiliate_commissions(id,platform,order_id,order_date,product_name,commission_amount,currency,status,source,imported_at)
          VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(platform,order_id) DO UPDATE SET order_date=excluded.order_date,product_name=excluded.product_name,commission_amount=excluded.commission_amount,currency=excluded.currency,status=excluded.status,source=excluded.source,imported_at=excluded.imported_at`)
          .bind(crypto.randomUUID(),platform,orderId,date,product,amount,currency,status,'csv_import',new Date().toISOString()).run();
        imported++;
      }
      return json({ ok: true, imported, rejected, summary: await affiliateSummary(env) });
    }
    if (path === 'report') {
      const days = Math.max(7, Math.min(90, Number(url.searchParams.get('days')) || 30));
      const token = await accessToken(env);
      const accountData = await googleGet('https://adsense.googleapis.com/v2/accounts?pageSize=100', token);
      const accounts = accountData.accounts || [];
      if (!accounts.length) return json({ error: 'Tidak ada akun AdSense yang dapat diakses oleh dickv940@gmail.com. Pastikan akun AdSense aktif dan izin API sudah diberikan.' }, 404);
      const account = accounts.find(x => x.name) || accounts[0];
      const today = new Date();
      const end = addDays(today, -1);
      const start = addDays(end, -(days - 1));
      const params = new URLSearchParams();
      params.set('dateRange', 'CUSTOM');
      const s = dateParts(start), e = dateParts(end);
      for (const [k,v] of Object.entries(s)) params.set('startDate.' + k, String(v));
      for (const [k,v] of Object.entries(e)) params.set('endDate.' + k, String(v));
      ['ESTIMATED_EARNINGS','PAGE_VIEWS','IMPRESSIONS','CLICKS','PAGE_CTR','PAGE_RPM'].forEach(v => params.append('metrics', v));
      params.append('dimensions', 'DATE');
      const report = await googleGet('https://adsense.googleapis.com/v2/' + account.name + '/reports:generate?' + params.toString(), token);
      const headers = (report.headers || []).map(h => ({ name: h.name, type: h.type, currencyCode: h.currencyCode || null }));
      const rows = (report.rows || []).map(row => {
        const values = row.cells || [];
        return Object.fromEntries(headers.map((h,i) => [h.name, values[i]?.value ?? null]));
      });
      const totals = report.totals?.cells || [];
      const total = Object.fromEntries(headers.map((h,i) => [h.name, totals[i]?.value ?? null]));
      return json({
        account: { name: account.name, displayName: account.displayName || null, timeZone: account.timeZone || null },
        period: { days, startDate: start.toISOString().slice(0,10), endDate: end.toISOString().slice(0,10) },
        currency: headers.find(h => h.name === 'ESTIMATED_EARNINGS')?.currencyCode || null,
        headers, rows, total, averages: report.averages?.cells || [], warnings: report.warnings || [],
        source: 'Google AdSense Management API v2',
        fetchedAt: new Date().toISOString()
      });
    }
    return json({ error: 'Endpoint AdSense tidak ditemukan.' }, 404);
  } catch (error) {
    console.error('VANNDIK AdSense', error);
    return json({ error: error?.message || 'Integrasi AdSense mengalami kesalahan.' }, 500);
  }
}
