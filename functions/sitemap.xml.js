const BASE='https://vanndik.pages.dev';
const staticPaths=['/','/tentang/','/berita/','/artikel/','/produk/','/aplikasi/','/game/'];
const xml=value=>String(value||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');
export async function onRequest({env}) {
  const urls=staticPaths.map(path=>({loc:BASE+path}));
  try {
    if(env.CMS_DB){
      await env.CMS_DB.prepare("CREATE TABLE IF NOT EXISTS cms_content_seo (content_id TEXT PRIMARY KEY,seo_title TEXT NOT NULL DEFAULT '',seo_description TEXT NOT NULL DEFAULT '',seo_keywords TEXT NOT NULL DEFAULT '',canonical_url TEXT NOT NULL DEFAULT '',og_image TEXT NOT NULL DEFAULT '',seo_score INTEGER NOT NULL DEFAULT 0,seo_checks TEXT NOT NULL DEFAULT '{}',updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
      const rows=await env.CMS_DB.prepare("SELECT c.slug,c.type,c.updated_at,c.published_at,s.canonical_url FROM cms_content c LEFT JOIN cms_content_seo s ON s.content_id=c.id WHERE c.status='published' OR (c.status='scheduled' AND c.published_at IS NOT NULL AND datetime(c.published_at)<=CURRENT_TIMESTAMP) ORDER BY c.updated_at DESC LIMIT 5000").all();
      for(const row of rows.results||[]){
        const loc=row.canonical_url&&/^https:\/\//i.test(row.canonical_url)?row.canonical_url:BASE+(row.type==='product'?'/produk/':'/konten/')+encodeURIComponent(row.slug)+'/';
        urls.push({loc,lastmod:row.updated_at||row.published_at||undefined});
      }
    }
  } catch(error) { console.error('VANNDIK sitemap',error); }
  const body='<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'+urls.map(item=>'  <url><loc>'+xml(item.loc)+'</loc>'+(item.lastmod?'<lastmod>'+xml(new Date(item.lastmod).toISOString())+'</lastmod>':'')+'</url>').join('\n')+'\n</urlset>';
  return new Response(body,{headers:{'content-type':'application/xml; charset=utf-8','cache-control':'public, max-age=300, stale-while-revalidate=600'}});
}
