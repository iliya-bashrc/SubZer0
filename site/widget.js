/* SubZer0 widget: today's patch-now CVEs for any site. Options in the URL: n=1..10, theme=dark|light, q=product filter. */
(function(){
  var P=new URLSearchParams(location.search),N=Math.max(1,Math.min(10,parseInt(P.get('n'),10)||5)),Q=(P.get('q')||'').toLowerCase().trim().slice(0,40);
  if(P.get('theme')==='light')document.documentElement.className='light';
  var SITE='https://iliya-bashrc.github.io/SubZer0/',COL={critical:'var(--crit)',high:'var(--high)',medium:'var(--med)',low:'var(--low)'};
  var ls=document.getElementById('ls'),when=document.getElementById('when');
  function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
  function ago(iso){var m=Math.max(0,Math.round((Date.now()-Date.parse(iso))/6e4));return m<60?m+'m ago':m<2880?Math.round(m/60)+'h ago':Math.round(m/1440)+'d ago'}
  function fit(){try{parent.postMessage({sz:'h',h:document.getElementById('w').offsetHeight+2},'*')}catch(e){}}
  function paint(d){var items=(d&&d.patch_now||[]).filter(function(r){return !Q||(String(r.products||'')+' '+String(r.title||'')).toLowerCase().indexOf(Q)>=0}).slice(0,N);
    ls.textContent='';if(d&&d.generated_at)when.textContent='updated '+ago(d.generated_at);
    if(!items.length){ls.appendChild(el('li','em',Q?'Nothing urgent for "'+Q+'" right now.':'Nothing urgent right now.'))}
    items.forEach(function(r){var li=el('li'),a=el('a');a.href=SITE+'cve/'+encodeURIComponent(r.id);a.target='_blank';a.rel='noopener';
      var sv=el('span','sv');sv.style.background=COL[r.severity]||'var(--ink3)';a.appendChild(sv);a.appendChild(el('span','id',r.id));
      var tg=el('span','tg');if(r.kev)tg.appendChild(el('i','k','KEV'));if(r.weaponized)tg.appendChild(el('i','','WEAPONIZED'));else if(r.public_exploit)tg.appendChild(el('i','','POC'));if(r.cvss)tg.appendChild(el('i','',(+r.cvss).toFixed(1)));a.appendChild(tg);
      a.appendChild(el('span','ti',r.title||''));a.title=(r.title||'')+(r.why?' · '+r.why:'');li.appendChild(a);ls.appendChild(li)});fit()}
  function load(){fetch('api/latest.json',{credentials:'omit'}).then(function(r){return r.ok?r.json():null}).then(paint).catch(function(){ls.textContent='';ls.appendChild(el('li','em','Could not load the feed. Try again later.'));fit()})}
  load();setInterval(load,30*60*1000);addEventListener('resize',fit);
})();
