const COOKIE = 'vanndik_cms_session';
const OWNER_EMAIL = 'dickv940@gmail.com';
const REDIRECT_URI = 'https://vanndik.pages.dev/api/cms/google-growth/callback';
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const uid = () => crypto.randomUUID();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const random = (n = 32) => [...crypto.getRandomValues(new Uint8Array(n))].map(x => x.toString(16).padStart(2, '0')).join('');
const sha = async value => b64(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));

async function ensureTables(env) {
  await env.CMS_DB.batch([
    env.CMS_DB.prepare(`CREATE TABLE IF NOT EXISTS cms_google_growth_connection (
      id TEXT PRIMARY KEY, google_email TEXT NOT NULL, refresh_token_enc TEXT NOT NULL,
      connected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    env.CMS_DB.prepare(`CREATE TABLE IF NOT EXISTS cms_google_growth_oauth_states (
      state TEXT PRIMARY KEY, expires_at TEXT NOT NULL
    )`),
    env.CMS_DB.prepare(`CREATE TABLE IF NOT EXISTS cms_google_growth_config (
      id TEXT PRIMARY KEY, search_console_site TEXT NOT NULL DEFAULT '',
      ga4_property_id TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`),
    env.CMS_DB.prepare(`INSERT OR IGNORE INTO cms_google_growth_config(id) VALUES('primary')`)
  ]);
}
async function adminFor(request, env) {
  const raw = (request.headers.get('cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1);
  if (!raw) return null;
  let token; try { token = decodeURIComponent(raw); } catch { return null; }
  return env.CMS_DB.prepare('SELECT a.id,a.email,a.role FROM cms_sessions s JOIN cms_admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>? AND a.active=1')
    .bind(await sha(token), new Date().toISOString()).first();
}
async function cryptoKey(env) {
  if (!env.GOOGLE_GROWTH_TOKEN_KEY) throw new Error('Secret GOOGLE_GROWTH_TOKEN_KEY belum diatur di Cloudflare.');
  const raw = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(env.GOOGLE_GROWTH_TOKEN_KEY));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function encrypt(value, env) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await cryptoKey(env), new TextEncoder().encode(value));
  const out = new Uint8Array(iv.length + encrypted.byteLength); out.set(iv); out.set(new Uint8Array(encrypted), iv.length); return b64(out);
}
async function decrypt(value, env) {
  const data = unb64(value), plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: data.slice(0, 12) }, await cryptoKey(env), data.slice(12));
  return new TextDecoder().decode(plain);
}
function redirect(origin, params) {
  const target = new URL('/admin/growth-settings/', origin);
  for (const [key, value] of Object.entries(params)) target.searchParams.set(key, value);
  return Response.redirect(target.toString(), 302);
}
async function getAccessToken(env) {
  const conn = await env.CMS_DB.prepare("SELECT * FROM cms_google_growth_connection WHERE id='primary'").first();
  if (!conn?.refresh_token_enc) throw new Error('Akun Google belum terhubung.');
  if (!env.GOOGLE_GROWTH_CLIENT_ID || !env.GOOGLE_GROWTH_CLIENT_SECRET) throw new Error('OAuth Google Growth belum dikonfigurasi di Cloudflare.');
  const refresh = await decrypt(conn.refresh_token_enc, env);
  const form = new URLSearchParams({ client_id: env.GOOGLE_GROWTH_CLIENT_ID, client_secret: env.GOOGLE_GROWTH_CLIENT_SECRET, refresh_token: refresh, grant_type: 'refresh_token' });
  const response = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form });
  const data = await response.json();
  if (!response.ok || !data.access_token) throw new Error('Token Google gagal diperbarui. Hubungkan ulang akun Google.');
  return data.access_token;
}
async function googleGet(url, token) {
  const response = await fetch(url, { headers: { Authorization: 'Bearer ' + token } });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error?.message || 'Google API gagal (' + response.status + ').');
  return data;
}
async function googlePost(url, token, payload) {
  const response = await fetch(url, { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: JSON.stringify(payload) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error?.message || 'Google API gagal (' + response.status + ').');
  return data;
}
function dateDaysAgo(days) { const d = new Date(); d.setUTCDate(d.getUTCDate() - days); return d.toISOString().slice(0, 10); }

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api\/cms\/google-growth\/?/, '').replace(/\/$/, '');
  const method = request.method.toUpperCase();
  try {
    if (!env.CMS_DB) return json({ error: 'Database CMS belum terhubung.' }, 503);
    if (method !== 'GET') {
      const origin = request.headers.get('origin');
      if (origin && origin !== url.origin) return json({ error: 'Origin tidak diizinkan.' }, 403);
    }
    await ensureTables(env);

    if (path === 'callback' && method === 'GET') {
      const code = url.searchParams.get('code'), state = url.searchParams.get('state');
      if (url.searchParams.get('error')) return redirect(url.origin, { google_error: 'consent_denied' });
      if (!code || !state) return redirect(url.origin, { google_error: 'invalid_callback' });
      const row = await env.CMS_DB.prepare('SELECT state FROM cms_google_growth_oauth_states WHERE state=? AND expires_at>?').bind(state, new Date().toISOString()).first();
      if (!row) return redirect(url.origin, { google_error: 'state_expired' });
      await env.CMS_DB.prepare('DELETE FROM cms_google_growth_oauth_states WHERE state=?').bind(state).run();
      if (!env.GOOGLE_GROWTH_CLIENT_ID || !env.GOOGLE_GROWTH_CLIENT_SECRET) return redirect(url.origin, { google_error: 'oauth_not_configured' });
      const form = new URLSearchParams({ code, client_id: env.GOOGLE_GROWTH_CLIENT_ID, client_secret: env.GOOGLE_GROWTH_CLIENT_SECRET, redirect_uri: REDIRECT_URI, grant_type: 'authorization_code' });
      const response = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form });
      const token = await response.json();
      if (!response.ok || !token.access_token) return redirect(url.origin, { google_error: 'token_exchange_failed' });
      const identity = await googleGet('https://openidconnect.googleapis.com/v1/userinfo', token.access_token);
      if (String(identity.email || '').toLowerCase() !== OWNER_EMAIL) return redirect(url.origin, { google_error: 'wrong_google_account' });
      const old = await env.CMS_DB.prepare("SELECT refresh_token_enc FROM cms_google_growth_connection WHERE id='primary'").first();
      const refresh = token.refresh_token || (old?.refresh_token_enc ? await decrypt(old.refresh_token_enc, env) : null);
      if (!refresh) return redirect(url.origin, { google_error: 'refresh_token_missing' });
      await env.CMS_DB.prepare("INSERT INTO cms_google_growth_connection(id,google_email,refresh_token_enc,connected_at) VALUES('primary',?,?,?) ON CONFLICT(id) DO UPDATE SET google_email=excluded.google_email,refresh_token_enc=excluded.refresh_token_enc,connected_at=excluded.connected_at")
        .bind(OWNER_EMAIL, await encrypt(refresh, env), new Date().toISOString()).run();
      return redirect(url.origin, { google_connected: '1' });
    }

    const admin = await adminFor(request, env);
    if (!admin) return json({ error: 'Silakan login sebagai admin VANNDIK.' }, 401);

    if (path === 'connect' && method === 'GET') {
      if (!env.GOOGLE_GROWTH_CLIENT_ID || !env.GOOGLE_GROWTH_CLIENT_SECRET || !env.GOOGLE_GROWTH_TOKEN_KEY)
        return json({ error: 'Atur GOOGLE_GROWTH_CLIENT_ID, GOOGLE_GROWTH_CLIENT_SECRET, dan GOOGLE_GROWTH_TOKEN_KEY di Cloudflare Pages terlebih dahulu.' }, 503);
      const state = random();
      await env.CMS_DB.prepare('DELETE FROM cms_google_growth_oauth_states WHERE expires_at<?').bind(new Date().toISOString()).run();
      await env.CMS_DB.prepare('INSERT INTO cms_google_growth_oauth_states(state,expires_at) VALUES(?,?)').bind(state, new Date(Date.now() + 10 * 60 * 1000).toISOString()).run();
      const auth = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      auth.searchParams.set('client_id', env.GOOGLE_GROWTH_CLIENT_ID);
      auth.searchParams.set('redirect_uri', REDIRECT_URI);
      auth.searchParams.set('response_type', 'code');
      auth.searchParams.set('scope', 'openid email https://www.googleapis.com/auth/webmasters.readonly https://www.googleapis.com/auth/analytics.readonly');
      auth.searchParams.set('access_type', 'offline');
      auth.searchParams.set('prompt', 'consent');
      auth.searchParams.set('include_granted_scopes', 'true');
      auth.searchParams.set('state', state);
      return Response.redirect(auth.toString(), 302);
    }
    if (path === 'status' && method === 'GET') {
      const [conn, config] = await Promise.all([
        env.CMS_DB.prepare("SELECT google_email,connected_at FROM cms_google_growth_connection WHERE id='primary'").first(),
        env.CMS_DB.prepare("SELECT search_console_site,ga4_property_id,updated_at FROM cms_google_growth_config WHERE id='primary'").first()
      ]);
      return json({ configured: !!(env.GOOGLE_GROWTH_CLIENT_ID && env.GOOGLE_GROWTH_CLIENT_SECRET && env.GOOGLE_GROWTH_TOKEN_KEY), connected: !!conn, email: conn?.google_email || null, connectedAt: conn?.connected_at || null, searchConsoleSite: config?.search_console_site || '', ga4PropertyId: config?.ga4_property_id || '' });
    }
    if (path === 'config' && method === 'POST') {
      const data = await request.json();
      const site = String(data.searchConsoleSite || '').trim().slice(0, 500);
      const property = String(data.ga4PropertyId || '').trim().replace(/^properties\//, '').slice(0, 40);
      if (site && !/^(sc-domain:[A-Za-z0-9.-]+|https?:\/\/.+)$/i.test(site)) return json({ error: 'Format properti Search Console tidak valid. Gunakan sc-domain:domain.com atau URL prefix lengkap.' }, 400);
      if (property && !/^\d+$/.test(property)) return json({ error: 'GA4 Property ID harus berupa angka.' }, 400);
      await env.CMS_DB.prepare("UPDATE cms_google_growth_config SET search_console_site=?,ga4_property_id=?,updated_at=? WHERE id='primary'").bind(site, property, new Date().toISOString()).run();
      return json({ ok: true });
    }
    if (path === 'report' && method === 'GET') {
      const days = Math.max(7, Math.min(90, Number(url.searchParams.get('days')) || 30));
      const config = await env.CMS_DB.prepare("SELECT search_console_site,ga4_property_id FROM cms_google_growth_config WHERE id='primary'").first();
      if (!config?.search_console_site && !config?.ga4_property_id) return json({ error: 'Masukkan properti Search Console atau GA4 terlebih dahulu.' }, 400);
      const token = await getAccessToken(env);
      const result = { periodDays: days, searchConsole: null, analytics: null, warnings: [] };
      if (config.search_console_site) {
        try {
          const data = await googlePost('https://searchconsole.googleapis.com/webmasters/v3/sites/' + encodeURIComponent(config.search_console_site) + '/searchAnalytics/query', token, {
            startDate: dateDaysAgo(days + 3), endDate: dateDaysAgo(3), dimensions: ['date'], rowLimit: 90
          });
          result.searchConsole = { rows: data.rows || [], clicks: (data.rows || []).reduce((n, r) => n + Number(r.clicks || 0), 0), impressions: (data.rows || []).reduce((n, r) => n + Number(r.impressions || 0), 0) };
        } catch (e) { result.warnings.push('Search Console: ' + e.message); }
      }
      if (config.ga4_property_id) {
        try {
          const data = await googlePost('https://analyticsdata.googleapis.com/v1beta/properties/' + config.ga4_property_id + ':runReport', token, {
            dateRanges: [{ startDate: days + 'daysAgo', endDate: 'yesterday' }],
            metrics: [{ name: 'totalUsers' }, { name: 'sessions' }, { name: 'screenPageViews' }],
            dimensions: [{ name: 'date' }], limit: 90
          });
          const totals = data.rows || [];
          result.analytics = { rows: totals, totals: (data.totals?.[0]?.metricValues || []).map((x, i) => ({ metric: ['users','sessions','pageViews'][i], value: Number(x.value || 0) })) };
        } catch (e) { result.warnings.push('GA4: ' + e.message); }
      }
      return json(result);
    }
    return json({ error: 'Endpoint Google Growth tidak ditemukan.' }, 404);
  } catch (error) {
    console.error('VANNDIK Google Growth', error);
    return json({ error: error?.message || 'Integrasi Google Growth mengalami kesalahan.' }, 500);
  }
}