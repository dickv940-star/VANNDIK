const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'public, max-age=60, stale-while-revalidate=300'}});
export async function onRequest({request,env}){
  if(request.method!=='GET')return json({error:'Method not allowed'},405);
  if(!env.CMS_DB)return json({error:'CMS database unavailable'},503);
  const url=new URL(request.url),path=url.pathname.replace(/^\/api\/public\/?/,'').replace(/\/$/,'');
  try{
    if(path==='content'){
      const slug=url.searchParams.get('slug')||'';
      if(slug){const item=await env.CMS_DB.prepare("SELECT id,type,title,slug,excerpt,body,image_url,category,tags,published_at FROM cms_content WHERE slug=? AND status='published' LIMIT 1").bind(slug).first();return item?json({item}):json({error:'Content not found'},404);}
      const type=url.searchParams.get('type')||'';
      if(type&&!['article','news','product','game','app'].includes(type))return json({items:[]});
      const rows=await env.CMS_DB.prepare("SELECT id,type,title,slug,excerpt,body,image_url,category,tags,status,affiliate_url,target_url,price,featured,sort_order,published_at,created_at,updated_at FROM cms_content WHERE status='published' AND (?='' OR type=?) ORDER BY featured DESC,sort_order ASC,published_at DESC,created_at DESC LIMIT 100").bind(type,type).all();
      return json({items:rows.results||[]});
    }
    if(path==='settings'){
      const rows=await env.CMS_DB.prepare("SELECT key,value FROM cms_site_settings WHERE key LIKE 'theme.%' OR key LIKE 'site.%'").all();
      return json({settings:Object.fromEntries((rows.results||[]).map(row=>[row.key,(()=>{try{return JSON.parse(row.value)}catch{return row.value}})()]))});
    }
    return json({error:'Not found'},404);
  }catch(error){console.error('VANNDIK public API',error);return json({error:'Unable to load public data'},500);}
}