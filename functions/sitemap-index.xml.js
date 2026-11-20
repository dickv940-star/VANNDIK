export async function onRequest() {
  const body='<?xml version="1.0" encoding="UTF-8"?>\n<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://vanndik.pages.dev/sitemap.xml</loc></sitemap></sitemapindex>';
  return new Response(body,{headers:{'content-type':'application/xml; charset=utf-8','cache-control':'public, max-age=300'}});
}
