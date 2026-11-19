(() => {
  const page = document.body.dataset.cmsPage || 'home';
  const allowed = value => typeof value === 'string' && (/^https?:\/\//i.test(value) || value.startsWith('/'));
  const escapeText = value => String(value || '');
  const setVar = (name,value) => { if(typeof value==='string' && /^#[0-9a-f]{3,8}$/i.test(value)) document.documentElement.style.setProperty(name,value); };
  const cardStyle = document.createElement('style');
  cardStyle.textContent = '.cms-published-card{overflow:hidden;min-width:0;border:1px solid rgba(120,150,190,.25);border-radius:8px;background:linear-gradient(145deg,#101827,#090d15);color:#f4f6fb;transition:transform .2s,border-color .2s}.cms-published-card:hover{transform:translateY(-3px);border-color:var(--cms-accent,#42d9ff)}.cms-published-card[hidden]{display:none!important}.cms-published-card .cms-card-art{height:155px;display:grid;place-items:center;overflow:hidden;background:radial-gradient(circle at 50% 45%,var(--cms-primary,#1769ff55),#101827 68%);color:#eaf5ff;font:800 38px Manrope,sans-serif}.cms-published-card .cms-card-art img{width:100%;height:100%;object-fit:cover}.cms-published-card .cms-card-copy{padding:15px}.cms-published-card .cms-card-meta{display:flex;justify-content:space-between;gap:8px;color:var(--cms-accent,#42d9ff);font-size:8px;letter-spacing:1px}.cms-published-card h3{margin:10px 0 7px;color:#f4f6fb;font:700 16px/1.35 Manrope,sans-serif}.cms-published-card p{margin:0;color:#95a3b7;font-size:10px;line-height:1.7}.cms-published-card .cms-card-action{display:inline-block;margin-top:13px;color:var(--cms-accent,#42d9ff);font-size:9px;font-weight:700}.cms-published-card .cms-card-price{margin-top:8px;color:#fff;font-weight:700;font-size:11px}.cms-live-note{margin:0 0 14px;color:#8ea3c0;font-size:9px;letter-spacing:1px}.cms-live-card-link{display:block;color:inherit;text-decoration:none}';
  document.head.appendChild(cardStyle);

  async function loadSettings(){
    const response=await fetch('/api/public/settings');
    if(!response.ok)return;
    const data=await response.json(), settings=data.settings||{};
    const global=settings['theme.global']||{}, pageTheme=settings['theme.'+page]||{};
    const theme={...global,...pageTheme};
    setVar('--cms-primary',theme.primary);setVar('--cms-accent',theme.accent);setVar('--cms-bg',theme.background);
    if(theme.background){document.querySelector('meta[name="theme-color"]')?.setAttribute('content',theme.background);}
    const css=document.createElement('style');
    css.textContent=':root{--cms-primary:'+(/^\#[0-9a-f]{3,8}$/i.test(theme.primary||'')?theme.primary:'#1769ff')+';--cms-accent:'+(/^\#[0-9a-f]{3,8}$/i.test(theme.accent||'')?theme.accent:'#42d9ff')+';--cms-bg:'+(/^\#[0-9a-f]{3,8}$/i.test(theme.background||'')?theme.background:'#05060a')+'} .header-cta,.primary-link,.explore-button,.preview-cta{border-color:var(--cms-primary)!important} .desktop-nav a[aria-current="page"]::after,.main-nav a.active:after{background:linear-gradient(90deg,var(--cms-primary),var(--cms-accent))!important} .page-eyebrow,.article-kicker,.section-label,.section-kicker{color:var(--cms-accent)!important}';
    document.head.appendChild(css);
    const navItems=settings['site.navigation'];
    const nav=document.getElementById('mainNavigation');
    if(Array.isArray(navItems)&&navItems.length&&nav){
      const activePath=location.pathname;
      nav.replaceChildren();
      navItems.forEach(item=>{
        const label=Array.isArray(item)?item[0]:item.label;
        const href=Array.isArray(item)?item[1]:item.href;
        if(!label||!allowed(href))return;
        const link=document.createElement('a');link.textContent=label;link.href=href;
        if(href===activePath||href.replace(/\/$/,'')===activePath.replace(/\/$/,'')){link.classList.add('active');link.setAttribute('aria-current','page');}
        nav.appendChild(link);
      });
    }
    const footer=settings['site.footer']||{};
    const footerDesc=document.querySelector('.site-footer>p,.footer-main>p');
    if(footer.description&&footerDesc)footerDesc.textContent=footer.description;
    const copyright=document.querySelector('.footer-meta span,.footer-bottom span');
    if(footer.copyright&&copyright)copyright.textContent=footer.copyright;
  }

  function createCard(item,type){
    const article=document.createElement('article');article.className='cms-published-card';
    const href=type==='product'?(allowed(item.affiliate_url)?item.affiliate_url:'#'):(['game','app'].includes(type)&&allowed(item.target_url)?item.target_url:'/konten/?slug='+encodeURIComponent(item.slug));
    const external=type==='product'||(['game','app'].includes(type)&&allowed(item.target_url));
    const link=document.createElement('a');link.className='cms-live-card-link';link.href=href;
    if(external){link.target='_blank';link.rel='noopener noreferrer'+(type==='product'?' sponsored':'');}
    const art=document.createElement('div');art.className='cms-card-art';
    if(allowed(item.image_url)){const image=document.createElement('img');image.src=item.image_url;image.alt=item.title;image.loading='lazy';art.appendChild(image);}
    else art.textContent=type==='game'?'✦':type==='product'?'◇':type==='app'?'▦':type==='news'?'◷':'V.';
    const copy=document.createElement('div');copy.className='cms-card-copy';
    const meta=document.createElement('div');meta.className='cms-card-meta';
    const category=document.createElement('span');category.textContent=(item.category||type).toUpperCase();
    const date=document.createElement('span');date.textContent='VANNDIK';
    meta.append(category,date);
    const heading=document.createElement('h3');heading.textContent=item.title;
    const excerpt=document.createElement('p');excerpt.textContent=item.excerpt||'Temukan informasi selengkapnya di VANNDIK.';
    copy.append(meta,heading,excerpt);
    if(type==='product'&&item.price){const price=document.createElement('div');price.className='cms-card-price';price.textContent=item.price;copy.appendChild(price);}
    const action=document.createElement('span');action.className='cms-card-action';action.textContent=type==='product'?'LIHAT PRODUK ↗':type==='game'?'BUKA GAME ↗':type==='app'?'BUKA APLIKASI ↗':'BACA SELENGKAPNYA ↗';copy.appendChild(action);
    link.append(art,copy);article.appendChild(link);return article;
  }

  async function loadContent(){
    const map={article:'#articleGrid',news:'.news-cards',product:'.product-grid',game:'#gameGrid',app:'#appsGrid'};
    const type=page==='aplikasi'?'app':page;
    if(!map[type])return;
    const container=document.querySelector(map[type]);if(!container)return;
    const response=await fetch('/api/public/content?type='+encodeURIComponent(type));
    if(!response.ok)return;
    const data=await response.json(),items=data.items||[];
    if(!items.length)return;
    const staticCards=[...container.children].filter(child=>!child.classList.contains('cms-published-card'));
    staticCards.forEach(child=>child.hidden=true);
    items.forEach(item=>container.appendChild(createCard(item,type)));
    container.insertAdjacentHTML('beforebegin','<div class="cms-live-note">KONTEN TERBIT · '+items.length+' ITEM DARI VANNDIK CMS</div>');
  }

  loadSettings().catch(()=>{});
  loadContent().catch(()=>{});
})();