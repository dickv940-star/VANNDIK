const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'public, max-age=60, stale-while-revalidate=300'}});
export async function onRequest({request,env}){
  if(request.method!=='GET')return json({error:'Method not allowed'},405);
  if(!env.CMS_DB)return json({error:'CMS database unavailable'},503);
  await env.CMS_DB.prepare("CREATE TABLE IF NOT EXISTS cms_content_seo (content_id TEXT PRIMARY KEY,seo_title TEXT NOT NULL DEFAULT '',seo_description TEXT NOT NULL DEFAULT '',seo_keywords TEXT NOT NULL DEFAULT '',canonical_url TEXT NOT NULL DEFAULT '',og_image TEXT NOT NULL DEFAULT '',seo_score INTEGER NOT NULL DEFAULT 0,seo_checks TEXT NOT NULL DEFAULT '{}',updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
  const url=new URL(request.url),path=url.pathname.replace(/^\/api\/public\/?/,'').replace(/\/$/,'');
  try{
    if(path==='content'){
      const slug=url.searchParams.get('slug')||'';
      if(slug){const item=await env.CMS_DB.prepare("SELECT c.id,c.type,c.title,c.slug,c.excerpt,c.body,c.image_url,c.category,c.tags,c.published_at,s.seo_title,s.seo_description,s.seo_keywords,s.canonical_url,s.og_image,s.seo_score,s.seo_checks FROM cms_content c LEFT JOIN cms_content_seo s ON s.content_id=c.id WHERE c.slug=? AND (c.status='published' OR (c.status='scheduled' AND c.published_at IS NOT NULL AND datetime(c.published_at)<=CURRENT_TIMESTAMP)) LIMIT 1").bind(slug).first();return item?json({item}):json({error:'Content not found'},404);}
      const type=url.searchParams.get('type')||'';
      if(type&&!['article','news','product','game','app'].includes(type))return json({items:[]});
      const rows=await env.CMS_DB.prepare("SELECT c.id,c.type,c.title,c.slug,c.excerpt,c.body,c.image_url,c.category,c.tags,c.status,c.affiliate_url,c.target_url,c.price,c.featured,c.sort_order,c.published_at,c.created_at,c.updated_at,s.seo_title,s.seo_description,s.seo_keywords,s.canonical_url,s.og_image,s.seo_score FROM cms_content c LEFT JOIN cms_content_seo s ON s.content_id=c.id WHERE (c.status='published' OR (c.status='scheduled' AND c.published_at IS NOT NULL AND datetime(c.published_at)<=CURRENT_TIMESTAMP)) AND (?='' OR c.type=?) ORDER BY c.featured DESC,c.sort_order ASC,c.published_at DESC,c.created_at DESC LIMIT 100").bind(type,type).all();
      return json({items:rows.results||[]});
    }
    if(path==='settings'){
      const rows=await env.CMS_DB.prepare("SELECT key,value FROM cms_site_settings WHERE key LIKE 'theme.%' OR key LIKE 'site.%'").all();
      return json({settings:Object.fromEntries((rows.results||[]).map(row=>[row.key,(()=>{try{return JSON.parse(row.value)}catch{return row.value}})()]))});
    }
    return json({error:'Not found'},404);
  }catch(error){console.error('VANNDIK public API',error);return json({error:'Unable to load public data'},500);}
}