'use strict';
/* SubZer0 — static client. Every data file is SHA-256 checked against the manifest before use (fail closed). */
const TABS=['Briefing','Research','Dossier','Terminal'],SLUG=['','research','dossier','terminal'];
const BASE=new URL(document.baseURI),SNAP=new URL('snapshot/',BASE).href;
const fmt=n=>n==null?'—':Number(n).toLocaleString('en-US');
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const safeUrl=u=>{try{const x=new URL(u);return x.protocol==='https:'||x.protocol==='http:'?x.href:null}catch{return null}};
const CVE_RE=/^CVE-\d{4}-\d{4,}$/;
const SEV={critical:['crit','Critical'],high:['high','High'],medium:['med','Medium'],low:['low','Low'],none:['none','Unscored'],unknown:['none','Unscored']};
const chip=s=>`<span class="chip ${SEV[s][0]}">${SEV[s][1]}</span>`;
function prio(r){ if(r.k) return [1,'Patch now','On CISA KEV. Attackers are already using it.'];
  if(r.x&&(r.e||0)>=.1) return [1,'Patch now','Exploit code is public and EPSS is high'];
  if(r.c>=9||(r.c>=7&&(r.x||(r.e||0)>=.05))) return [2,'This week',r.x?'Exploit code is public':r.c>=9?'Critical score':'EPSS keeps going up'];
  if(r.c>=7) return [3,'Planned','High, but nobody is exploiting it yet'];
  return [4,'Track','Quiet for now'];}
let D=null,rows=[],BYID=new Map();
const REC=new Map();let EPSS=null;

/* ---------- verified data layer ---------- */
async function sha256Hex(buf){const d=await crypto.subtle.digest('SHA-256',buf);return [...new Uint8Array(d)].map(b=>b.toString(16).padStart(2,'0')).join('')}
async function fetchBuf(url,max){const r=await fetch(url,{cache:'no-cache',credentials:'omit'});if(!r.ok)throw new Error(`${r.status} for ${url}`);const b=await r.arrayBuffer();if(b.byteLength>max)throw new Error('file too large: '+url);return b}
async function fetchVerified(path,sha,max=8e6){if(!/^data\/[a-z0-9_.-]+\.json$/i.test(path)||!/^[0-9a-f]{64}$/i.test(sha))throw new Error('bad manifest entry: '+path);
  let b=await fetchBuf(SNAP+path,max);if((await sha256Hex(b))!==sha.toLowerCase()){b=await fetchBuf(SNAP+path+'?v='+sha.slice(0,12),max);if((await sha256Hex(b))!==sha.toLowerCase())throw new Error('integrity check failed: '+path)}
  return JSON.parse(new TextDecoder().decode(b))}
async function loadManifest(){const r=await fetch(SNAP+'manifest.json',{cache:'no-store',credentials:'omit'});if(!r.ok)throw new Error('manifest '+r.status);const t=await r.text();if(t.length>2e6)throw new Error('manifest too large');
  const m=JSON.parse(t);if(!m||!Array.isArray(m.days)||!m.search_index||!m.generated_at)throw new Error('manifest has an unexpected shape');return m}
async function loadAll(m){const [idx,poc]=await Promise.all([fetchVerified(m.search_index.path,m.search_index.sha256,2e7),m.poc_ids?fetchVerified(m.poc_ids.path,m.poc_ids.sha256,1e6):[]]);return build(m,idx,poc)}
function build(m,idx,poc){const P=new Set(Array.isArray(poc)?poc:[]);
  const R=[];for(const t of idx){if(!Array.isArray(t)||!CVE_RE.test(t[0]))continue;const s=SEV[t[2]]?t[2]:'unknown';
    const r={id:t[0],t:String(t[1]||''),s,c:+t[3]||0,k:t[4]?1:0,e:typeof t[5]==='number'?t[5]:null,a:String(t[6]||''),d:String(t[7]||t[6]||''),p:String(t[8]||''),x:P.has(t[0])?1:0};
    r.T=esc(r.t);r.Pr=esc([...new Set(r.p.toLowerCase().split(/\s+/).filter(Boolean))].join(' '));r._t=(r.id+' '+r.t+' '+r.p).toLowerCase();r.P=prio(r);R.push(r)}
  R.sort((a,b)=>b.d.localeCompare(a.d)||b.id.localeCompare(a.id,undefined,{numeric:true}));
  const src=(m.source_status||[]).map(s=>({n:String(s.name),ok:!!s.ok,v:s.records??s.advisories??s.catalog_records??s.exploit_cves??s.scores??null,at:String(s.checked_at||'')}));
  return {D:{m,gen:m.generated_at,totals:m.totals,days:m.days.map(d=>({d:d.date,n:d.count,c:d.critical,h:d.high,m:d.medium,l:d.low,x:d.exploited})),sources:src,poc:P.size},rows:R}}
function adopt(x){D=x.D;rows=x.rows;BYID=new Map(rows.map(r=>[r.id,r]))}
async function getRecord(id){if(REC.has(id))return REC.get(id);const r=BYID.get(id);if(!r)throw new Error(id+' is not in this snapshot');
  const day=D.m.days.find(d=>d.date===r.a);if(!day)throw new Error('no shard for '+r.a);const sh=await fetchVerified(day.path,day.sha256,2e7);
  const list=Array.isArray(sh)?sh:Object.values(sh);const rec=list.find(x=>x&&x.id===id);if(!rec)throw new Error(id+' missing from its shard');REC.set(id,{rec,sha:day.sha256});return REC.get(id)}
function getEpss(){if(!EPSS&&D.m.epss)EPSS=fetchVerified(D.m.epss.path,D.m.epss.sha256,2e7).then(j=>j&&j.scores||{}).catch(()=>({}));return EPSS||Promise.resolve({})}
async function epssSeries(id){try{const r=await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(id)}&scope=time-series`,{credentials:'omit',referrerPolicy:'no-referrer',signal:AbortSignal.timeout?AbortSignal.timeout(8000):undefined});if(!r.ok)return null;
  const j=await r.json();const d=j&&Array.isArray(j.data)&&j.data[0];if(!d)return null;
  const pts=[...(Array.isArray(d['time-series'])?d['time-series']:[]).map(x=>[x.date,+x.epss]),[d.date,+d.epss]].filter(p=>/^\d{4}-\d\d-\d\d$/.test(p[0])&&isFinite(p[1])&&p[1]>=0&&p[1]<=1).sort((a,b)=>a[0].localeCompare(b[0]));
  return pts.length>1?pts:null}catch{return null}}

/* ---------- glitch canvas (pixel-sort, VisionQuest credits palette) ---------- */
function glitch(cv,seed,tint){
  const dpr=Math.min(2,devicePixelRatio||1),w=cv.clientWidth,h=cv.clientHeight;cv.width=w*dpr;cv.height=h*dpr;
  const g=cv.getContext('2d');g.scale(dpr,dpr);let s=seed;const R=()=>(s=(s*16807)%2147483647)/2147483647;
  const pal=tint||['#D8C9B0','#BBA787','#E6DCC8','#1F4F6E','#143650','#2B6A8C','#A9472A','#7A3420','#E8892B','#0D1114','#0D1114','#59626A'];
  g.fillStyle='#0D1114';g.fillRect(0,0,w,h);
  let x=0;while(x<w){const cw=4+Math.floor(R()*R()*46);let y=0;
    while(y<h){const bh=6+Math.floor(R()*R()*140);g.fillStyle=pal[Math.floor(R()*pal.length)];g.fillRect(x,y,cw,bh);
      if(R()<.22){const p=4+Math.floor(R()*6);for(let yy=y;yy<y+bh;yy+=p)for(let xx=x;xx<x+cw;xx+=p){if(R()<.35){g.fillStyle=pal[Math.floor(R()*pal.length)];g.fillRect(xx,yy,p,p)}}}
      y+=bh}
    x+=cw}
  g.globalAlpha=.5;for(let i=0;i<40;i++){g.fillStyle=R()<.5?'#E6DCC8':'#2B6A8C';g.fillRect(R()*w,0,1,h)}
  g.globalAlpha=.10;g.strokeStyle='#E6DCC8';for(let i=0;i<w;i+=24){g.beginPath();g.moveTo(i,0);g.lineTo(i,h);g.stroke()}for(let j=0;j<h;j+=24){g.beginPath();g.moveTo(0,j);g.lineTo(w,j);g.stroke()}
  g.globalAlpha=.55;g.fillStyle='#F2EEE6';g.font='9px JetBrains Mono, monospace';
  const code=['def get_identity_vector(self):','    return self.cvss.vector','kev = catalog.lookup(cve_id)','if epss.percentile > 0.95:','    queue.push(cve, prio=P1)','sha256(manifest) == expected'];
  for(let i=0;i<code.length;i++)g.fillText(code[i],w*.52,h*.18+i*12);
  g.globalAlpha=1;}

/* ---------- navigation (swipe + tabs + keys) ---------- */
let cur=0;const track=document.getElementById('track');
function renderNav(){
  document.getElementById('tabs').innerHTML=TABS.map((t,i)=>`<button class="tab" data-i="${i}" ${i===cur?'aria-current="page"':''}><i>0${i+1}</i>${t}</button>`).join('')+'<span class="tab-ind" id="ind"></span>';
  document.getElementById('bnav').innerHTML=TABS.map((t,i)=>`<button data-i="${i}" ${i===cur?'aria-current="page"':''}><i>0${i+1}</i>${t}</button>`).join('');
  document.querySelectorAll('[data-i]').forEach(b=>b.onclick=()=>go(+b.dataset.i));
  const a=document.querySelector('.tab[aria-current]'),ind=document.getElementById('ind');
  if(a&&ind){ind.style.width=a.offsetWidth-28+'px';ind.style.transform=`translateX(${a.offsetLeft+14}px)`}
}
function routeURL(){let p=SLUG[cur];if(cur===1){const u=new URLSearchParams();if(F.q)u.set('q',F.q);if(F.view!=='all')u.set('view',F.view);const q=u.toString();if(q)p+='?'+q}return new URL(p,BASE).href}
function go(i){cur=Math.max(0,Math.min(3,i));track.style.transform=`translateX(${-cur*25}%)`;renderNav();if(typeof sheetOpen!=='undefined'&&!sheetOpen&&rows.length)history.replaceState(null,'',routeURL());document.title=(cur?TABS[cur]+' · ':'')+'SubZer0'}
(function swipe(){let x0,y0,dx=0,lock=null;const vp=document.getElementById('vp');
  vp.addEventListener('pointerdown',e=>{if(e.pointerType==='mouse')return;x0=e.clientX;y0=e.clientY;dx=0;lock=null});
  vp.addEventListener('pointermove',e=>{if(x0==null)return;const mx=e.clientX-x0,my=e.clientY-y0;
    if(lock==null&&Math.hypot(mx,my)>8)lock=Math.abs(mx)>Math.abs(my)?'x':'y';
    if(lock==='x'){dx=mx;track.classList.add('dragging');track.style.transform=`translateX(calc(${-cur*25}% + ${dx/ (cur===0&&dx>0||cur===3&&dx<0?3:1)}px))`}});
  const end=()=>{if(x0==null)return;track.classList.remove('dragging');if(lock==='x'&&Math.abs(dx)>60)go(cur+(dx<0?1:-1));else go(cur);x0=null};
  vp.addEventListener('pointerup',end);vp.addEventListener('pointercancel',end);})();
addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key>='1'&&e.key<='4'){e.preventDefault();go(+e.key-1)}
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();go(1);setTimeout(()=>document.getElementById('q').focus(),300)}
  if(e.key==='Escape')closeSheet()});
document.getElementById('searchBtn').onclick=()=>{go(1);setTimeout(()=>document.getElementById('q').focus(),300)};

/* ---------- briefing ---------- */
function sinceLast(){let prev=LS.get('seen',null);const ids=rows.map(r=>r.id),kev=rows.filter(r=>r.k).map(r=>r.id);
  if(!prev||prev.gen!==D.gen){if(prev&&typeof prev.ids==='string'){const pi=new Set(prev.ids.split(',')),pk=new Set((prev.kev||'').split(','));LS.set('seen',{gen:D.gen,ids:ids.join(','),kev:kev.join(','),last:{n:ids.filter(i=>!pi.has(i)).length,k:kev.filter(i=>!pk.has(i)).length}})}else LS.set('seen',{gen:D.gen,ids:ids.join(','),kev:kev.join(',')})}
  const cur=LS.get('seen',null);if(!cur||!cur.last)return'';const n=cur.last.n,k=cur.last.k;
  return `<br><span style="color:var(--strip)">since your last visit: ${n} new, ${k} added to KEV</span>`}
function briefing(){
  const T=D.totals,q=rows.filter(r=>r.P[0]<=2).sort((a,b)=>a.P[0]-b.P[0]||(b.e||0)-(a.e||0)).slice(0,7);
  const feed=rows.filter(r=>r.c>0).slice(0,7),days=D.days,max=Math.max(...days.map(d=>d.n));
  const bw=100/days.length;let bars='';
  days.forEach((d,i)=>{let y=200;[['l','--low'],['m','--med'],['h','--high'],['c','--crit']].forEach(([k,c])=>{const hh=d[k]/max*190;y-=hh;bars+=`<rect x="${i*bw+bw*.18}%" y="${y}" width="${bw*.64}%" height="${hh}" fill="var(${c})" opacity="${k==='c'?1:.78}"/>`});
    const rest=(d.n-d.c-d.h-d.m-d.l)/max*190;if(rest>0){y-=rest;bars+=`<rect x="${i*bw+bw*.18}%" y="${y}" width="${bw*.64}%" height="${rest}" fill="#3A3F46"/>`}
    if(d.x)bars+=`<rect x="${i*bw+bw*.18}%" y="${y-8}" width="${bw*.64}%" height="3" fill="var(--ink)"/>`});
  document.getElementById('p0').innerHTML=`<div class="wrap">
  <div class="hero"><canvas id="hc"></canvas><div class="strip"></div>
    <div class="hero-copy"><span class="chip crit">Last 30 days</span>
      <div class="credit-name">${fmt(T.cves)} <span>CVEs</span></div>
      <div class="sub">${fmt(T.critical)} critical, ${T.known_exploited} already being exploited, ${fmt(D.poc)} with exploit code out in public.</div>
      <div class="code">search index sha256 ✓ · ${D.sources.filter(s=>s.ok).length}/${D.sources.length} sources healthy · last sync ${D.gen.replace('T',' ').slice(0,16)} UTC${sinceLast()}</div></div>
    <div class="hero-meta"><span class="chip ice">Live</span><div class="code">next refresh in <span id="cd"></span></div></div>
  </div>
  <div class="stats">
    <div class="stat"><span class="chip crit">Patch now</span><div class="v">${rows.filter(r=>r.P[0]===1).length}</div><div class="s">fix these first</div></div>
    <div class="stat"><span class="chip high">Critical</span><div class="v">${fmt(T.critical)}</div><div class="s">CVSS 9.0 and up</div></div>
    <div class="stat"><span class="chip med">High</span><div class="v">${fmt(T.high)}</div><div class="s">CVSS 7.0 to 8.9</div></div>
    <div class="stat"><span class="chip info">Exploited</span><div class="v">${T.known_exploited}</div><div class="s">added to CISA KEV</div></div>
    <div class="stat"><span class="chip low">Public PoC</span><div class="v">${fmt(D.poc)}</div><div class="s">exploit code is out</div></div>
  </div>
  <div class="cols">
    <section><div class="sec-h"><h2>Patch queue</h2><span class="meta">exploited stuff goes on top</span></div>
      ${q.map(r=>`<button class="queue-item" data-cve="${r.id}">
        <div class="prio">P${r.P[0]}<small style="color:${r.P[0]===1?'var(--crit)':'var(--high)'}">${r.P[1]}</small></div>
        <div style="min-width:0"><div style="display:flex;align-items:center;gap:10px">${chip(r.s)}<span class="id">${r.id}</span>${r.k?'<span class="kev">KEV</span>':''}${r.x?'<span class="poc">POC</span>':''}</div>
          <div class="why">${r.T}</div><div class="code">› ${r.P[2]}${r.p?' · '+r.Pr:''}</div></div>
        <div class="epss">${r.e!=null?(r.e*100).toFixed(1)+'% EPSS':'— EPSS'}<span class="bar"><i style="width:${(r.e||0)*100}%"></i></span></div>
        <div class="cvss">${r.c>0?r.c.toFixed(1):'—'}</div></button>`).join('')}
    </section>
    <section class="feed"><div class="sec-h"><h2>Live feed</h2><span class="meta" id="feedMeta">updates by itself</span></div><div id="feed">
      ${feed.map(r=>feedItem(r)).join('')}</div></section>
  </div>
  <section class="mystack" id="mystack"></section>
  <section class="chart"><div class="sec-h"><h2>What got published</h2><span class="meta">last 30 days by severity. ▬ means exploited</span></div>
    <svg viewBox="0 0 1000 200" preserveAspectRatio="none">${bars}</svg>
    <div class="legend"><span><i style="background:var(--crit)"></i>Critical</span><span><i style="background:var(--high)"></i>High</span><span><i style="background:var(--med)"></i>Medium</span><span><i style="background:var(--low)"></i>Low</span><span><i style="background:#3A3F46"></i>Unscored</span></div></section>
  <section style="margin-top:48px"><div class="sec-h"><h2>Where the data comes from</h2><span class="meta">your browser checks the SHA-256 of every file</span></div>
    <div class="sources">${D.sources.map(s=>`<div class="src"><div class="n"><i></i>${esc(s.n)}</div><div class="v">${s.v==null?"—":fmt(s.v)}</div><div class="s">${s.ok?'checked '+esc((s.at||'').replace('T',' ').slice(5,16)):'<span style="color:var(--crit)">failed last run</span>'}</div></div>`).join('')}</div></section>
  </div>`;
  requestAnimationFrame(()=>glitch(document.getElementById('hc'),7));renderMyStack();
}
function renderMyStack(){const el=document.getElementById('mystack');if(!el)return;
  if(!ST.stack.length){el.innerHTML=`<div class="sec-h"><h2>Your stack</h2><span class="meta">stays in this browser</span></div><div class="ms-empty" style="margin-top:16px"><span>Tell SubZer0 what you run and it'll keep those CVEs right here.</span><input id="msIn" placeholder="wordpress, fortinet, nginx… then enter" maxlength="120"></div>`;
    const i=document.getElementById('msIn');i.onkeydown=e=>{if(e.key==='Enter'){i.value.split(',').forEach(stackAdd)}};return}
  const m=rows.filter(inStack).sort((a,b)=>a.P[0]-b.P[0]||(b.e||0)-(a.e||0));
  el.innerHTML=`<div class="sec-h"><h2>Your stack</h2><span class="meta">${ST.stack.map(esc).join(', ')} · <a href="#research" data-mystack style="color:var(--ice)">edit</a></span></div>
    <div class="sb" style="margin-top:16px">${m.length?m.slice(0,6).map(r=>`<button class="ms-item" data-cve="${r.id}"><div style="display:flex;gap:6px">${chip(r.s)}<span class="chip ${r.P[0]===1?'crit':r.P[0]===2?'high':'none'}">P${r.P[0]}</span></div><div class="id">${r.id}</div><div class="t">${esc(r.t)}</div></button>`).join(''):`<div class="ms-empty" style="border:0">Nothing in the last 30 days matches your stack. Enjoy it while it lasts.</div>`}</div>`;
  el.querySelector('[data-mystack]').onclick=e=>{e.preventDefault();F.view='stack';go(1);draw()}}
const feedItem=(r,n)=>`<button class="feed-item${n?' new':''}" data-cve="${r.id}"><time>${n?'now':r.d.slice(5)}</time><div>${chip(r.s)}<div class="id">${r.id}</div><div class="t">${r.T}</div></div></button>`;

/* ---------- local state: watchlist + stack (never leaves the browser) ---------- */
const LS={get(k,d){try{return JSON.parse(localStorage.getItem('sz.'+k))??d}catch{return d}},set(k,v){try{localStorage.setItem('sz.'+k,JSON.stringify(v))}catch{}}};
const ST={watch:new Set(LS.get('watch',[])),stack:LS.get('stack',[])};
const saveST=()=>{LS.set('watch',[...ST.watch]);LS.set('stack',ST.stack)};
const txt=r=>r._t;
const inStack=r=>ST.stack.length>0&&ST.stack.some(k=>txt(r).includes(k));
function toggleWatch(id){ST.watch.has(id)?ST.watch.delete(id):ST.watch.add(id);saveST();refreshAll();return ST.watch.has(id)}
function stackAdd(k){k=String(k).trim().toLowerCase().slice(0,40);if(!k||ST.stack.includes(k))return false;ST.stack.push(k);saveST();refreshAll();return true}
function stackRm(k){ST.stack=ST.stack.filter(x=>x!==k);saveST();refreshAll()}
function refreshAll(){if(document.getElementById('tb'))draw();renderMyStack()}
function snack(m){let s=document.getElementById('snack');if(!s){s=document.createElement('div');s.id='snack';s.className='snack';s.setAttribute('role','status');document.body.appendChild(s)}s.textContent=m;s.classList.add('on');clearTimeout(s._t);s._t=setTimeout(()=>s.classList.remove('on'),1800)}
async function copy(t,m){try{await navigator.clipboard.writeText(t)}catch{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove()}snack(m||'copied')}
const SITE='https://iliya-bashrc.github.io/SubZer0';

/* ---------- query language: kev:yes epss>0.5 cvss>=9 sev:critical vendor:apache -wordpress "exact phrase" ---------- */
const yes=v=>['yes','y','true','1','on'].includes(v);
function pred(k,op,v){const n=parseFloat(v),cmp=a=>op==='>'?a>n:op==='>='?a>=n:op==='<'?a<n:op==='<='?a<=n:a>=n;
  switch(k){case 'kev':return r=>!!r.k===yes(v);case 'poc':case 'exploit':return r=>!!r.x===yes(v);
    case 'epss':{const m=n>1?n/100:n;return r=>{const a=r.e||0;return op==='>'?a>m:op==='<'?a<m:op==='<='?a<=m:a>=m}}
    case 'cvss':case 'score':return r=>cmp(r.c||0);
    case 'sev':case 'severity':return r=>r.s.startsWith(v);
    case 'p':case 'prio':case 'priority':return op===':'?r=>r.P[0]===n:r=>cmp(r.P[0]);
    case 'vendor':case 'product':case 'in':return r=>txt(r).includes(v);
    case 'after':case 'since':return r=>r.d>=v;case 'before':return r=>r.d<=v;
    case 'is':return v==='watched'?r=>ST.watch.has(r.id):v==='mine'||v==='stack'?inStack:v==='kev'?r=>!!r.k:null;
    default:return r=>txt(r).includes(k+op+v)}}
function parseQ(q){const ps=[];const re=/(-?)(?:([a-z]+)(:|>=|<=|>|<)("[^"]*"|\S+)|"([^"]+)"|(\S+))/gi;let m;
  while((m=re.exec(q||''))){let p;if(m[2]){p=pred(m[2].toLowerCase(),m[3],m[4].replace(/"/g,'').toLowerCase())}else{const w=(m[5]??m[6]).toLowerCase();p=r=>txt(r).includes(w)}
    if(p)ps.push(m[1]?r=>!p(r):p)}
  return r=>ps.every(p=>p(r))}

/* ---------- export (CSV is formula-injection safe) ---------- */
function download(name,data,type){const u=URL.createObjectURL(new Blob([data],{type}));const a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1000)}
const csvCell=v=>{let s=String(v??'');if(/^[=+\-@\t\r]/.test(s))s="'"+s;return /[",\n]/.test(s)?'"'+s.replace(/"/g,'""')+'"':s};
function exportRows(list,kind){const recs=list.map(r=>({id:r.id,priority:'P'+r.P[0],severity:r.s,cvss:r.c||null,epss:r.e??null,kev:!!r.k,poc:!!r.x,published:r.d,title:r.t,url:'https://nvd.nist.gov/vuln/detail/'+r.id}));
  const stamp=D.gen.slice(0,10);
  if(kind==='json')download(`subzer0-${stamp}.json`,JSON.stringify(recs,null,2),'application/json');
  else download(`subzer0-${stamp}.csv`,[Object.keys(recs[0]||{id:''}).join(','),...recs.map(o=>Object.values(o).map(csvCell).join(','))].join('\n'),'text/csv');
  snack(`exported ${recs.length} rows`)}

/* ---------- research ---------- */
let F={sev:new Set(),kev:false,poc:false,epss:false,q:'',sort:'P',view:'all'};
{const u=new URLSearchParams(location.search);if(u.has('q')||u.has('view')){F.q=(u.get('q')||'').slice(0,200);F.view=['all','p1','stack','watch'].includes(u.get('view'))?u.get('view'):'all'}}
let LIST=[];
let SHOWN=200;
function research(){
  document.getElementById('p1').innerHTML=`<div class="wrap">
    <div class="r-head"><div><span class="chip ice">Research</span><div class="credit-name">Dig in</div></div>
      <div class="views" id="views" role="toolbar" aria-label="Views"></div></div>
    <label class="r-search"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--ink3)" stroke-width="1.8"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></svg>
      <input id="q" placeholder="CVE ID, vendor, keyword… or kev:yes epss>0.5 vendor:apache" autocomplete="off" spellcheck="false"></label>
    <div class="qhint">try ${['kev:yes','epss>50','cvss>=9','sev:critical -wordpress','poc:yes after:2026-10-15','is:watched'].map(x=>`<code data-q="${x}">${x}</code>`).join('')}</div>
    <div id="stackbar"></div>
    <div class="filters" id="filters"></div>
    <table><colgroup><col style="width:78px"><col style="width:156px"><col><col style="width:110px"><col style="width:70px"><col style="width:120px"><col style="width:56px"><col style="width:56px"><col style="width:104px"></colgroup>
      <thead><tr><th data-s="P">Priority</th><th data-s="id">CVE</th><th>Title · product</th><th data-s="s">Severity</th><th data-s="c">CVSS</th><th data-s="e">EPSS</th><th>KEV</th><th>PoC</th><th data-s="d">Published</th></tr></thead>
      <tbody id="tb"></tbody></table>
    <div class="cards" id="cards"></div>
    <button class="btn more" id="more" hidden>Show more</button>
    <div class="r-foot"><span id="cnt"></span><div class="acts"><button class="btn" id="exCsv">Export CSV</button><button class="btn" id="exJson">Export JSON</button><button class="btn" id="cpLink">Copy link</button></div></div></div>`;
  const qi=document.getElementById('q');qi.value=F.q;qi.oninput=e=>{F.q=e.target.value;SHOWN=200;draw()};
  document.getElementById('more').onclick=()=>{SHOWN+=200;draw()};
  const io=new IntersectionObserver(es=>{if(es[0].isIntersecting&&!document.getElementById('more').hidden){SHOWN+=200;draw()}},{rootMargin:'400px'});io.observe(document.getElementById('more'));
  document.querySelectorAll('[data-q]').forEach(c=>c.onclick=()=>{F.q=c.dataset.q;qi.value=F.q;SHOWN=200;draw()});
  document.getElementById('exCsv').onclick=()=>exportRows(LIST,'csv');document.getElementById('exJson').onclick=()=>exportRows(LIST,'json');
  document.getElementById('cpLink').onclick=()=>{const u=new URLSearchParams();if(F.q)u.set('q',F.q);if(F.view!=='all')u.set('view',F.view);copy(SITE+'/research'+(u.toString()?'?'+u:''),'link copied')};
  document.querySelectorAll('th[data-s]').forEach(th=>th.onclick=()=>{F.sort=th.dataset.s;draw()});
  draw();
}
function draw(){
  const VW=[['all','All',rows.length],['p1','Patch now',rows.filter(r=>r.P[0]===1).length],['stack','My stack',rows.filter(inStack).length],['watch','Watchlist',rows.filter(r=>ST.watch.has(r.id)).length]];
  document.getElementById('views').innerHTML=VW.map(([k,l,n])=>`<button data-v="${k}" aria-pressed="${F.view===k}">${l}<small>${n}</small></button>`).join('');
  document.querySelectorAll('[data-v]').forEach(b=>b.onclick=()=>{F.view=b.dataset.v;SHOWN=200;draw()});
  const sb=document.getElementById('stackbar');
  sb.innerHTML=F.view==='stack'?`<div class="stackbar"><span class="label">My stack</span>${ST.stack.map(k=>`<span class="kw">${esc(k)}<button data-rm="${esc(k)}" aria-label="remove ${esc(k)}">×</button></span>`).join('')}<input id="stIn" placeholder="${ST.stack.length?'add another…':'what do you run? e.g. wordpress, fortinet, nginx'}" maxlength="40"></div>`:'';
  sb.querySelectorAll('[data-rm]').forEach(b=>b.onclick=()=>stackRm(b.dataset.rm));
  const si=document.getElementById('stIn');if(si)si.onkeydown=e=>{if(e.key==='Enter'&&si.value.trim()){stackAdd(si.value);setTimeout(()=>document.getElementById('stIn')?.focus(),0)}};
  const fl=[['critical','crit'],['high','high'],['medium','med'],['low','low']];
  document.getElementById('filters').innerHTML=fl.map(([s,c])=>`<button class="f" data-sev="${s}" aria-pressed="${F.sev.has(s)}"><span class="sw" style="background:var(--${c})"></span>${SEV[s][1]}</button>`).join('')+
   `<span class="f-sep"></span><button class="f" data-t="kev" aria-pressed="${F.kev}">CISA KEV</button><button class="f" data-t="poc" aria-pressed="${F.poc}">Public PoC</button><button class="f" data-t="epss" aria-pressed="${F.epss}">EPSS ≥ 10%</button>`;
  document.querySelectorAll('[data-sev]').forEach(b=>b.onclick=()=>{const s=b.dataset.sev;F.sev.has(s)?F.sev.delete(s):F.sev.add(s);SHOWN=200;draw()});
  document.querySelectorAll('[data-t]').forEach(b=>b.onclick=()=>{F[b.dataset.t]=!F[b.dataset.t];SHOWN=200;draw()});
  const so={P:(a,b)=>a.P[0]-b.P[0]||(b.e||0)-(a.e||0),id:(a,b)=>b.id.localeCompare(a.id),s:(a,b)=>b.c-a.c,c:(a,b)=>b.c-a.c,e:(a,b)=>(b.e||0)-(a.e||0),d:(a,b)=>b.d.localeCompare(a.d)};
  const qp=parseQ(F.q),vp={all:()=>true,p1:r=>r.P[0]===1,stack:inStack,watch:r=>ST.watch.has(r.id)}[F.view];
  const list=LIST=rows.filter(r=>vp(r)&&(!F.sev.size||F.sev.has(r.s))&&(!F.kev||r.k)&&(!F.poc||r.x)&&(!F.epss||(r.e||0)>=.1)&&qp(r)).sort(so[F.sort]);
  document.querySelectorAll('th[data-s]').forEach(th=>th.classList.toggle('sorted',th.dataset.s===F.sort));
  const shown=list.slice(0,SHOWN);
  document.getElementById('tb').innerHTML=shown.map(r=>`<tr data-cve="${r.id}"><td><span class="chip ${r.P[0]===1?'crit':r.P[0]===2?'high':'none'}">P${r.P[0]}</span></td><td class="t-id">${r.id}${ST.watch.has(r.id)?'<span class="star" title="watching">★</span>':''}</td>
    <td><div class="t-title">${r.T}</div><div class="code t-prod">${r.p?r.Pr:'—'}${inStack(r)?'<span class="mine">your stack</span>':''}</div></td><td>${chip(r.s)}</td>
    <td class="num" style="font-size:16px;font-weight:600">${r.c>0?r.c.toFixed(1):'<span class="muted">—</span>'}</td>
    <td><div class="epss">${r.e!=null?(r.e*100).toFixed(2)+'%':'<span class="muted">—</span>'}<span class="bar"><i style="width:${(r.e||0)*100}%"></i></span></div></td>
    <td>${r.k?'<span class="kev">KEV</span>':'<span class="muted">—</span>'}</td><td>${r.x?'<span class="poc">POC</span>':'<span class="muted">—</span>'}</td><td class="mono muted">${r.d}</td></tr>`).join('');
  document.getElementById('cards').innerHTML=shown.map(r=>`<button class="card" data-cve="${r.id}"><div class="row">${chip(r.s)}<span class="chip ${r.P[0]===1?'crit':r.P[0]===2?'high':'none'}">P${r.P[0]}</span>${r.k?'<span class="kev">KEV</span>':''}${r.x?'<span class="poc">POC</span>':''}<span class="mono muted" style="margin-left:auto;font-size:12px">${r.d.slice(5)}</span></div>
    <div class="t-id" style="margin-top:10px">${r.id}${ST.watch.has(r.id)?'<span class="star">★</span>':''}${inStack(r)?'<span class="mine">your stack</span>':''}</div><div class="t-title">${r.T}</div><div class="m"><span>CVSS ${r.c>0?r.c.toFixed(1):'—'}</span><span>EPSS ${r.e!=null?(r.e*100).toFixed(1)+'%':'—'}</span></div></button>`).join('');
  document.getElementById('cnt').textContent=`showing ${fmt(shown.length)} of ${fmt(list.length)} matches · ${fmt(rows.length)} CVEs in the window`;
  const mb=document.getElementById('more');mb.hidden=list.length<=SHOWN;mb.textContent=`Show ${fmt(Math.min(200,list.length-SHOWN))} more`;
  if(cur===1&&!sheetOpen)history.replaceState(null,'',routeURL());
  if(!list.length){const e={watch:'Nothing on your watchlist yet. Open any CVE and hit <b>Watch</b>, or type <b>watch CVE-…</b> in the terminal.',stack:ST.stack.length?'None of the CVEs in this window match your stack. Good news, honestly.':'Add the vendors and products you actually run. SubZer0 will pin their CVEs for you. It stays in this browser only.'}[F.view]||'No match. Try a looser query.';
    document.getElementById('tb').innerHTML=`<tr><td colspan="9"><div class="empty">${e}</div></td></tr>`;document.getElementById('cards').innerHTML=`<div class="empty">${e}</div>`}
}

/* ---------- dossier ---------- */
const DC_TINT=['#3A0E12','#6E1A20','#E5323F','#0D1114','#0D1114','#1F4F6E','#D8C9B0','#0D1114'];
function dossierHTML(r,full,ep,inSheet){const id=r.id,rec=full&&full.rec,kev=rec&&rec.kev&&typeof rec.kev==='object'?rec.kev:null,P=r.P,sev=r.s,score=r.c;
  const vec=rec&&typeof rec.cvss_vector==='string'?rec.cvss_vector:'';const cwe=rec&&Array.isArray(rec.cwe)?rec.cwe.filter(x=>/^CWE-\d{1,5}$/.test(x)):[];
  const aff=rec&&Array.isArray(rec.affected)?rec.affected.slice(0,60):[];const refs=rec&&Array.isArray(rec.refs)?rec.refs.map(f=>({...f,u:safeUrl(f.url)})).filter(f=>f.u).slice(0,80):[];
  const a0=aff[0];const sub=vec||(a0?`${a0.vendor||''} ${a0.product||''}`.trim():'')||(r.p||'');
  const pct=ep&&typeof ep.percentile==='number'?ep.percentile:null;
  const dates=rec?[[rec.published,'Published'],kev&&[kev.date_added,'Added to CISA KEV',1],kev&&kev.due_date&&[kev.due_date,'CISA deadline for US agencies',1],[rec.modified,'Last modified']].filter(x=>x&&x[0]):[];
  const overdue=kev&&kev.due_date&&kev.due_date<new Date().toISOString().slice(0,10);
  return `<div class="d-hero"><canvas class="dc"></canvas>
    ${inSheet?'<button class="d-close" id="closeSheet">← Back · Esc</button>':''}
    <div style="display:flex;gap:8px;flex-wrap:wrap">${chip(sev)}${r.k?'<span class="chip crit outline">Exploited in the wild</span>':''}<span class="chip ${P[0]===1?'crit':P[0]===2?'high':'none'}">P${P[0]} · ${P[1]}</span></div>
    <div class="credit-name">${id}</div>
    <div class="code" style="margin-top:8px">${esc(sub)||'&nbsp;'}</div>
    <p class="lead">${esc(rec?rec.title:r.t)}</p>
    <div class="d-actions"><button class="btn primary" data-act="copy" data-id="${id}">Copy ID</button><button class="btn" data-act="share" data-id="${id}">Share link</button><button class="btn${ST.watch.has(id)?' on':''}" data-act="watch" data-id="${id}">${ST.watch.has(id)?'★ Watching':'☆ Watch'}</button><button class="btn" data-act="json" data-id="${id}">Export JSON</button><a class="btn" href="https://nvd.nist.gov/vuln/detail/${id}" target="_blank" rel="noopener noreferrer">NVD ↗</a></div></div>
  <div class="d-metrics">
    <div class="d-metric"><span class="label">CVSS</span><div class="v" style="color:var(--${SEV[sev][0]==='none'?'ink3':SEV[sev][0]})">${score>0?score.toFixed(1):'—'}<small>/10</small></div><div class="s">${vec?esc(vec.split('/')[0]):'base score'}</div></div>
    <div class="d-metric"><span class="label">EPSS</span><div class="v">${r.e!=null?(r.e*100).toFixed(1)+'<small>%</small>':'—'}</div><div class="s">${pct!=null?'higher than '+(pct*100).toFixed(1)+'% of CVEs':'not scored yet'}</div><div class="spark-wrap" data-spark="${id}"></div></div>
    <div class="d-metric"><span class="label">CISA KEV</span><div class="v" style="font-size:22px;margin-top:18px">${kev?esc(kev.date_added):r.k?'Listed':'Not listed'}</div><div class="s">${kev&&kev.due_date?`<span class="chip ${overdue?'crit':'high'}" style="height:18px;font-size:10px">Due ${esc(kev.due_date)}${overdue?' · overdue':''}</span>`:'—'}</div></div>
    <div class="d-metric"><span class="label">Exploit code</span><div class="v" style="font-size:22px;margin-top:18px">${r.x?'Public':'None seen'}</div><div class="s">${r.x?'Exploit-DB or tagged refs':'not in Exploit-DB'}</div></div>
  </div>
  <div class="d-body">
    <div class="why-box"><span class="chip ${P[0]===1?'crit':P[0]===2?'high':'none'}">Why P${P[0]}</span><p><b>${P[2].replace(/\.$/,'')}.</b>${pct!=null?` EPSS puts it above ${(pct*100).toFixed(1)}% of all CVEs.`:''}${kev&&kev.required_action?' CISA: '+esc(String(kev.required_action).slice(0,300)):''}</p></div>
    ${!full?`<p class="muted" id="dload">Loading the full record and checking its hash…</p>`:`
    ${rec.desc&&rec.desc.trim()!==String(rec.title).trim()?`<section><div class="sec-h"><h2>Description</h2><span class="meta">${esc((rec.date_basis||'').toLowerCase())}</span></div><p class="desc">${esc(rec.desc)}</p></section>`:''}
    ${kev?`<section><div class="sec-h"><h2>Exploitation</h2><span class="meta">CISA KEV</span></div>
      <dl class="kv"><dt>Vendor</dt><dd>${esc(kev.vendor)} · ${esc(kev.product)}</dd>${kev.ransomware?`<dt>Ransomware</dt><dd>${esc(kev.ransomware)}</dd>`:''}<dt>Added</dt><dd class="mono">${esc(kev.date_added)}</dd>${kev.due_date?`<dt>Due</dt><dd class="mono">${esc(kev.due_date)}</dd>`:''}</dl></section>`:''}
    ${cwe.length?`<section><div class="sec-h"><h2>Weakness</h2><span class="meta">MITRE CWE</span></div><div class="tags" style="margin-top:14px">${cwe.map(c=>`<a class="tag" href="https://cwe.mitre.org/data/definitions/${c.slice(4)}.html" target="_blank" rel="noopener noreferrer">${c}</a>`).join('')}</div></section>`:''}
    ${aff.length?`<section><div class="sec-h"><h2>Affected · ${rec.affected.length}</h2><span class="meta">vendor / product</span></div>
      ${aff.map(a=>`<div class="ref"><div style="min-width:0"><div class="l">${esc(a.vendor||'—')} · ${esc(a.product||'—')}</div><div class="code" style="margin-top:4px">${esc(a.versions||a.cpe||'versions not listed')}</div></div></div>`).join('')}</section>`:''}
    ${dates.length?`<section><div class="sec-h"><h2>Timeline</h2></div><div class="timeline">${dates.map(([d,l,hot])=>`<div class="tl${hot?' hot':''}"><time>${esc(String(d).slice(0,10))}</time><i></i><div>${l}</div></div>`).join('')}</div></section>`:''}
    ${refs.length?`<section><div class="sec-h"><h2>References · ${refs.length}</h2><span class="meta">open in a new tab</span></div>
      ${refs.map(f=>`<a class="ref" href="${esc(f.u)}" target="_blank" rel="noopener noreferrer nofollow"><div style="min-width:0"><div class="d">${esc(new URL(f.u).host)}</div><div class="l">${esc(f.label||'Reference')}</div>${Array.isArray(f.tags)&&f.tags.length?`<div class="tags">${f.tags.slice(0,6).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</div>`:''}</div></a>`).join('')}</section>`:''}
    <p class="proto-note">record checked against shard sha256 ${full.sha.slice(0,16)}…</p>`}
  </div>`}
async function fillDossier(el,id,inSheet){const r=BYID.get(id);if(!r){el.innerHTML=`<div class="empty"><b>${esc(id)}</b> isn't in the current 30-day snapshot.</div>`;return}
  el.innerHTML=dossierHTML(r,null,null,inSheet);paintDossier(el,inSheet);
  try{const [full,ep]=await Promise.all([getRecord(id),getEpss().then(s=>s[id]||null)]);if(el.dataset.id!==id)return;el.innerHTML=dossierHTML(r,full,ep,inSheet);paintDossier(el,inSheet);
    if(r.e!=null)epssSeries(id).then(pts=>{const w=el.querySelector(`[data-spark="${id}"]`);if(!w||!pts)return;const mx=Math.max(...pts.map(p=>p[1]),.01);
      w.innerHTML=`<svg class="spark" viewBox="0 0 100 36" preserveAspectRatio="none" role="img" aria-label="EPSS over the last ${pts.length} days"><polyline points="${pts.map((p,i)=>`${(i/(pts.length-1)*100).toFixed(2)},${(34-p[1]/mx*32).toFixed(2)}`).join(' ')}" fill="none" stroke="var(--ice)" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg><div class="code" style="margin-top:4px">${pts.length} days · live from FIRST</div>`})}
  catch(e){const l=el.querySelector('#dload');if(l)l.innerHTML=`<span style="color:var(--crit)">Couldn't verify this record (${esc(e.message)}). Nothing unverified is shown.</span>`}}
function paintDossier(el,inSheet){if(inSheet){const c=el.querySelector('#closeSheet');if(c)c.onclick=closeSheet}requestAnimationFrame(()=>el.querySelectorAll('.dc').forEach(c=>glitch(c,11,DC_TINT)))}
function dossierTab(id){id=id||LS.get('last',null);if(!id||!BYID.has(id)){const top=rows.filter(r=>r.P[0]===1).sort((a,b)=>(b.e||0)-(a.e||0))[0]||rows[0];id=top&&top.id}
  const p=document.getElementById('p2');p.innerHTML=`<div style="max-width:980px;margin:0 auto" id="dtab"></div>`;const el=document.getElementById('dtab');if(!id)return;el.dataset.id=id;fillDossier(el,id,false)}

/* sheet with swipe-back + history */
const sheet=document.getElementById('sheet'),back=document.getElementById('back');let sheetOpen=false,lastFocus=null;
function openSheet(id,replace){if(!CVE_RE.test(id))return;lastFocus=document.activeElement;sheet.dataset.id=id;sheet.scrollTop=0;fillDossier(sheet,id,true);sheet.classList.add('on');back.classList.add('on');sheetOpen=true;
  LS.set('last',id);const u=new URL('cve/'+id,BASE).href;replace?history.replaceState({sheet:1},'',u):history.pushState({sheet:1},'',u);document.title=id+' · SubZer0';setTimeout(()=>sheet.focus({preventScroll:true}),50)}
function closeSheet(fromPop){if(!sheetOpen)return;sheetOpen=false;sheet.classList.remove('on');back.classList.remove('on');sheet.style.transform='';
  if(fromPop!==true)history.back();setTimeout(()=>{if(!sheetOpen)history.replaceState(null,'',routeURL())},0);document.title=(cur?TABS[cur]+' · ':'')+'SubZer0';if(lastFocus&&lastFocus.focus)lastFocus.focus({preventScroll:true})}
back.onclick=closeSheet;addEventListener('popstate',e=>{if(sheetOpen)closeSheet(true);else{const m=location.pathname.match(/\/cve\/(CVE-\d{4}-\d{4,})$/);if(m)openSheet(m[1],true)}});
addEventListener('keydown',e=>{if(e.key==='Escape'&&sheetOpen)closeSheet()});
(function(){let x0,dx=0,lock=null,y0;sheet.addEventListener('pointerdown',e=>{if(e.pointerType==='mouse')return;x0=e.clientX;y0=e.clientY;dx=0;lock=null});
  sheet.addEventListener('pointermove',e=>{if(x0==null)return;const mx=e.clientX-x0,my=e.clientY-y0;if(lock==null&&Math.hypot(mx,my)>8)lock=Math.abs(mx)>Math.abs(my)&&mx>0?'x':'y';
    if(lock==='x'){dx=Math.max(0,mx);sheet.classList.add('dragging');sheet.style.transform=`translateX(${dx}px)`;back.style.opacity=1-dx/innerWidth}});
  const end=()=>{if(x0==null)return;sheet.classList.remove('dragging');back.style.opacity='';if(lock==='x'&&dx>90)closeSheet();else sheet.style.transform='';x0=null};
  sheet.addEventListener('pointerup',end);sheet.addEventListener('pointercancel',end)})();
document.addEventListener('click',e=>{const a=e.target.closest('[data-act]');if(a){const id=a.dataset.id;
    if(a.dataset.act==='copy')copy(id,id+' copied');
    if(a.dataset.act==='share'){const u=SITE+'/cve/'+id;navigator.share&&matchMedia('(pointer:coarse)').matches?navigator.share({title:id,url:u}).catch(()=>{}):copy(u,'link copied')}
    if(a.dataset.act==='watch'){const on=toggleWatch(id);document.querySelectorAll(`[data-act="watch"][data-id="${id}"]`).forEach(b=>{b.classList.toggle('on',on);b.textContent=on?'★ Watching':'☆ Watch'});snack(on?'added to watchlist':'removed from watchlist')}
    if(a.dataset.act==='json'){const f=REC.get(id);const r=BYID.get(id);download(id+'.json',JSON.stringify(f?{...f.rec,epss:r&&r.e,poc:!!(r&&r.x)}:r?{id:r.id,title:r.t,severity:r.s,cvss:r.c,epss:r.e,kev:!!r.k,poc:!!r.x}:{id},null,2),'application/json')}
    return}
  const t=e.target.closest('[data-cve]');if(t&&CVE_RE.test(t.dataset.cve))openSheet(t.dataset.cve)});

/* ---------- terminal ---------- */
const CMDS=[['./info','about this thing'],['./help','what you can type'],['./latest','newest CVEs'],['./kev','being exploited right now'],['./status','are the feeds ok?'],['./bugcod3','BugCod3 on Telegram',1],['./rootaccessclub','RootAccessClub on Telegram',1],['./clear','wipe the screen']];
const EXTRA=['cve ','search ','watch ','unwatch ','watchlist','stack','stack add ','stack rm ','export csv','export json','whoami','date','ls','uname -a','history','banner','sudo','exit'];
const P_='<span class="p-user">user@subzer0</span><span class="t-dim">:</span><span class="p-path">~</span><span class="t-dim">$</span>';
const GL={S:[' ████','█    ',' ███ ','    █','████ '],U:['█   █','█   █','█   █','█   █',' ███ '],B:['████ ','█   █','████ ','█   █','████ '],Z:['█████','   █ ','  █  ',' █   ','█████'],E:['█████','█    ','████ ','█    ','█████'],R:['████ ','█   █','████ ','█  █ ','█   █'],'0':[' ███ ','█  ██','█ █ █','██  █',' ███ ']};
const BANNER=[0,1,2,3,4].map(r=>[...'SUBZER0'].map(ch=>GL[ch][r].replace(/█/g,'██').replace(/ /g,'  ')).join('  ')).join('\n');
const ZERO=GL['0'].map(r=>r.replace(/█/g,'██').replace(/ /g,'  ')).join('\n');
let hist=[],hi=0,busy=false,queue=[];
const wait=ms=>new Promise(r=>setTimeout(r,ms));
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
function sizeBanner(){const o=document.getElementById('to');if(!o)return;const w=o.clientWidth-56;o.style.setProperty('--bfs',Math.max(3.4,Math.min(11,w/(BANNER.split('\n')[0].length*0.6)))+'px');
  const cols=Math.floor(o.clientWidth/7.8),rows=Math.floor(o.clientHeight/22.75);const g=document.getElementById('tgeo');if(g)g.textContent=`${cols}×${rows}`}
function terminal(){const el=document.getElementById('p3');el.innerHTML=`<div class="term-wrap">
  <div class="term" role="region" aria-label="SubZer0 terminal">
    <div class="term-top"><span class="dots"><i></i><i></i><i></i></span><span class="ttl" style="font:500 12px var(--mono);letter-spacing:0;text-transform:none">user@subzer0: ~ — sz-sh</span><span class="sp"><span class="code" id="tgeo"></span><span class="chip low">tty1</span></span></div>
    <div class="term-out" id="to" aria-live="polite"></div>
    <label class="term-in" id="tin">${P_}<span class="tv" id="tv"></span><span class="cursor"></span><input id="ti" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" aria-label="Command"><span class="hint">tab complete · ↑ history · ctrl+l clear</span></label>
  </div>
  <aside class="deck" aria-label="Commands">
    <div class="deck-h"><span class="label">Command deck</span><span class="code">${CMDS.length}</span></div>
    <div class="deck-list">${CMDS.map(([c,d,tg],i)=>`<button data-c="${c}" class="${tg?'tg':''}"><kbd>${String(i+1).padStart(2,'0')}</kbd><div class="c">${c}</div><div class="d">${d}</div></button>`).join('')}</div>
    <div class="deck-foot">try <b>search kev:yes</b>, <b>cve &lt;id&gt;</b>, <b>stack add nginx</b><br>snapshot <b>${D.gen.slice(0,16).replace('T',' ')} UTC</b></div>
  </aside></div>`;
  const ti=document.getElementById('ti'),tv=document.getElementById('tv');
  el.querySelectorAll('[data-c]').forEach(b=>b.onclick=()=>{exec(b.dataset.c,true);if(matchMedia('(hover:hover)').matches)ti.focus()});
  ti.addEventListener('input',()=>{tv.textContent=ti.value});
  ti.addEventListener('keydown',e=>{
    if(e.key==='Enter'){const v=ti.value.trim();ti.value='';tv.textContent='';exec(v,false)}
    else if(e.key==='ArrowUp'){if(hi>0){hi--;ti.value=hist[hi];tv.textContent=ti.value}e.preventDefault()}
    else if(e.key==='ArrowDown'){hi=Math.min(hist.length,hi+1);ti.value=hist[hi]||'';tv.textContent=ti.value}
    else if(e.key==='Tab'){const v=ti.value.trim();if(!v)return;e.preventDefault();const all=[...CMDS.map(x=>x[0]),...EXTRA];const m=all.filter(c=>c.startsWith(v)||c.startsWith('./'+v));
      if(m.length===1){ti.value=m[0];tv.textContent=m[0]}else if(m.length>1)print(`<div class="ln">${P_} ${esc(v)}</div><div class="ln t-dim">${m.join('   ')}</div>`)}
    else if(e.key==='l'&&e.ctrlKey){e.preventDefault();document.getElementById('to').innerHTML=''}
    else if(e.key==='c'&&e.ctrlKey&&!getSelection().toString()){e.preventDefault();print(`<div class="ln">${P_} ${esc(ti.value)}<span class="t-dim">^C</span></div>`);ti.value='';tv.textContent=''}});
  new ResizeObserver(sizeBanner).observe(document.getElementById('to'));
  boot()}
function print(h){const o=document.getElementById('to');o.insertAdjacentHTML('beforeend',h);o.scrollTop=o.scrollHeight}
async function lines(arr,gap=28){for(const l of arr){print(l);if(!reduce)await wait(gap)}}
async function typeOut(c){const tv=document.getElementById('tv');tv.textContent='';if(!reduce)for(const ch of c){tv.textContent+=ch;await wait(28+Math.random()*38)}else tv.textContent=c;await wait(120);tv.textContent=''}
async function exec(c,typed){if(busy){queue.push([c,typed]);return}busy=true;document.getElementById('tin').classList.add('busy');
  if(typed)await typeOut(c);
  if(c){hist.push(c);hi=hist.length}
  await run(c);
  busy=false;document.getElementById('tin').classList.remove('busy');if(queue.length){const [a,b]=queue.shift();exec(a,b)}}
async function boot(){document.getElementById('to').innerHTML='';busy=true;document.getElementById('tin').classList.add('busy');
  const now=new Date();
  await lines([`<div class="ln t-dim">SubZer0 OS 2.0 LTS (sz-sh) — tty1</div>`,`<div class="ln"> </div>`],60);
  print(`<div class="ln">subzer0 login: <span id="lg"></span><span class="cur"></span></div>`);
  const lg=document.getElementById('lg');for(const ch of 'user'){lg.textContent+=ch;if(!reduce)await wait(70)}document.querySelector('#to .cur')?.remove();
  await lines([`<div class="ln">Last login: ${now.toUTCString().slice(0,25)} on tty1</div>`,`<div class="ln"> </div>`,
    `<div class="ln"><span class="t-ok">[  OK  ]</span> Mounted snapshot <span class="t-dim">snapshot/manifest.json</span></div>`,
    `<div class="ln"><span class="t-ok">[  OK  ]</span> Verified sha256 <span class="t-dim">index + ${D.m.days.length} day shards checked against manifest</span></div>`,
    `<div class="ln"><span class="t-ok">[  OK  ]</span> Reached feeds <span class="t-dim">${D.sources.filter(s=>s.ok).length}/${D.sources.length} sources healthy</span></div>`,
    `<div class="ln"><span class="t-ok">[  OK  ]</span> Indexed <span class="t-dim">${D.totals.cves.toLocaleString()} CVEs · ${D.totals.known_exploited} KEV · ${D.poc} PoC</span></div>`,
    `<div class="ln"><span class="t-ok">[  OK  ]</span> Started live watcher <span class="t-dim">polling every 60s</span></div>`],110);
  print(`<pre class="banner" aria-label="SubZer0">${BANNER}</pre>`);sizeBanner();
  await lines([`<div class="ln t-dim">made by <span class="t-ice">@BugCod3</span> and <span class="t-ice">@RootAccessClub</span>. for learning, not for breaking things.</div>`,
    `<div class="ln">lost? type <span class="t-ice">help</span>.</div>`,`<div class="ln"> </div>`],60);
  busy=false;document.getElementById('tin').classList.remove('busy');if(queue.length){const [a,b]=queue.shift();exec(a,b)}}
const sevc=s=>SEV[s][0]==='none'?'ink3':SEV[s][0];
async function run(raw){let c=raw.trim().replace(/\s+/g,' ');const lc=c.toLowerCase();const head=`<div class="ln">${P_} ${esc(c)}</div>`;
  let k=lc;if(k&&!k.startsWith('./')&&CMDS.some(x=>x[0]==='./'+k))k='./'+k;
  if(k==='./clear'){document.getElementById('to').innerHTML='';return}
  print(head);if(!k)return;
  const kv=(a,b)=>`<span class="t-ice">${a}</span><span>${b}</span>`;
  if(k==='./info'){print(`<div class="neo"><pre class="banner">${ZERO}</pre><div class="tgrid">
    <span class="t-ice" style="grid-column:1/-1">user@subzer0</span><span class="t-dim" style="grid-column:1/-1">────────────</span>
    ${kv('OS','SubZer0 OS 2.0 LTS')}${kv('Shell','sz-sh 0.1')}${kv('Window','30 days · rolling')}${kv('CVEs',D.totals.cves.toLocaleString())}${kv('Feeds','NVD · GHSA · KEV · EPSS · Exploit-DB')}${kv('Refresh','6h · live diff 60s')}${kv('Creators','@BugCod3 · @RootAccessClub')}${kv('Use','learning only')}
    <span style="grid-column:1/-1" class="swatch">${['crit','high','med','low','info','ice','strip','ink'].map(v=>`<i style="background:var(--${v})"></i>`).join('')}</span></div></div>`);}
  else if(k==='./help'||k==='help'){await lines([`<div class="ln t-dim">commands:</div>`,`<div class="tgrid">${CMDS.map(([x,d])=>`<span class="t-ice">${x}</span><span class="t-dim">${d}</span>`).join('')}</div>`,`<div class="tgrid" style="margin-top:8px">${[['cve <id>','details for one CVE'],['search <query>','same syntax as the search box'],['watch <id>','add to your watchlist'],['watchlist','what you are watching'],['stack add <name>','tell it what you run'],['export csv|json','download the current data']].map(([a,b])=>`<span class="t-ice">${esc(a)}</span><span class="t-dim">${b}</span>`).join('')}</div><div class="ln t-dim">also: whoami · ls · date · uname -a · history · banner</div>`])}
  else if(k==='./latest'){print(`<div class="ln t-dim">pulling the latest…</div>`);if(!reduce)await wait(260);
    const g=`<div class="tgrid c3" id="lg3"><span class="t-dim">ID</span><span class="t-dim">SEVERITY</span><span class="t-dim">SUMMARY</span></div>`;print(g);const G=[...document.querySelectorAll('#lg3')].pop();G.removeAttribute('id');
    for(const r of rows.slice(0,6)){G.insertAdjacentHTML('beforeend',`<div class="tr" data-cve="${r.id}"><span>${r.id}</span><span style="color:var(--${sevc(r.s)})">${SEV[r.s][1].toUpperCase()}</span><span class="t-dim">${esc(r.t)}</span></div>`);document.getElementById('to').scrollTop=1e9;if(!reduce)await wait(45)}
    print(`<div class="ln t-dim">click a row to open it</div>`)}
  else if(k==='./kev'){const ks=rows.filter(r=>r.k).slice(0,6);print(`<div class="tgrid c3"><span class="t-dim">ID</span><span class="t-dim">STATUS</span><span class="t-dim">SUMMARY</span>${ks.map(r=>`<div class="tr" data-cve="${r.id}"><span>${r.id}</span><span class="t-err">KEV</span><span class="t-dim">${esc(r.t)}</span></div>`).join('')}</div><div class="ln t-dim">${ks.length} of ${D.totals.known_exploited} known-exploited shown</div>`)}
  else if(k==='./status'){await lines([...D.sources.map(s=>`<div class="ln"><span class="${s.ok?'t-ok':'t-err'}">[${s.ok?'  OK  ':' FAIL '}]</span> ${esc(s.n)} <span class="t-dim">· ${(+s.v||0).toLocaleString()} records</span></div>`),`<div class="ln t-dim">generated ${D.gen.replace('T',' ').replace('Z',' UTC')} · sha256(manifest) verified</div>`],90)}
  else if(k==='./bugcod3'||k==='./rootaccessclub'){const n=k==='./bugcod3'?'BugCod3':'RootAccessClub';
    await lines([`<div class="ln"><span class="t-dim">→</span> resolving t.me/${n} … <span class="t-ok">ok</span></div>`],0);
    print(`<div class="ln"><span class="t-dim">→</span> opening Telegram <span class="t-warn" id="pb"></span></div>`);const pb=[...document.querySelectorAll('#pb')].pop();
    for(let i=0;i<=10;i++){pb.textContent=`[${'█'.repeat(i)}${'░'.repeat(10-i)}] ${i*10}%`;await wait(90)}pb.removeAttribute('id');
    if(!window.SZ_NOREDIRECT)location.href='https://t.me/'+n}
  else if(/^cve(\s|$)/.test(lc)){const id=(c.split(' ')[1]||'').toUpperCase();const r=BYID.get(id)||null;
    if(!id)print(`<div class="ln">usage: cve <span class="t-dim">CVE-YYYY-NNNN</span></div>`);
    else if(!r)print(`<div class="ln t-err">${esc(id)}: not in this snapshot</div>`);
    else print(`<div class="tgrid">${kv('id',`<span data-cve="${r.id}" style="cursor:pointer;text-decoration:underline">${r.id}</span>`)}${kv('severity',`<span style="color:var(--${sevc(r.s)})">${SEV[r.s][1]}</span>${r.c>0?' '+(+r.c).toFixed(1):''}`)}${kv('priority','P'+r.P[0]+' '+esc(r.P[1]))}${kv('epss',r.e!=null?(r.e*100).toFixed(2)+'%':'n/a')}${kv('kev',r.k?'<span class="t-err">yes</span>':'no')}${kv('poc',r.x?'<span class="t-warn">public</span>':'none')}${kv('published',r.d)}${kv('summary',`<span class="t-dim" style="white-space:normal">${esc(r.t)}</span>`)}${kv('watching',ST.watch.has(r.id)?'★ yes':'no <span class="t-dim">(watch '+r.id+')</span>')}</div>`)}
  else if(/^(search|grep)(\s|$)/.test(lc)){const q=c.replace(/^\S+\s*/,'');if(!q){print(`<div class="ln">usage: search <span class="t-dim">kev:yes epss>0.5 vendor:apache</span></div>`)}else{const m=rows.filter(parseQ(q)).sort((a,b)=>a.P[0]-b.P[0]||(b.e||0)-(a.e||0));
    print(`<div class="tgrid c3"><span class="t-dim">ID</span><span class="t-dim">PRIO</span><span class="t-dim">SUMMARY</span>${m.slice(0,10).map(r=>`<div class="tr" data-cve="${r.id}"><span>${r.id}</span><span style="color:var(--${r.P[0]===1?'crit':r.P[0]===2?'high':'ink3'})">P${r.P[0]}</span><span class="t-dim">${esc(r.t)}</span></div>`).join('')}</div><div class="ln t-dim">${m.length} match${m.length===1?'':'es'}${m.length>10?', showing 10':''}</div>`)}}
  else if(/^(un)?watch(\s|$)/.test(lc)){const id=(c.split(' ')[1]||'').toUpperCase();const un=lc.startsWith('un');
    if(!/^CVE-\d{4}-\d{4,}$/.test(id))print(`<div class="ln">usage: ${un?'un':''}watch <span class="t-dim">CVE-YYYY-NNNN</span></div>`);
    else{if(ST.watch.has(id)===un)toggleWatch(id);print(`<div class="ln">${un?'stopped watching':'<span class="t-warn">★</span> watching'} ${id}</div>`)}}
  else if(lc==='watchlist'){const w=[...ST.watch];print(w.length?w.map(id=>{const r=rows.find(x=>x.id===id);return `<div class="ln"><span class="t-warn">★</span> <span data-cve="${id}" style="cursor:pointer">${id}</span> <span class="t-dim">${r?esc(r.t.slice(0,70)):''}</span></div>`}).join(''):`<div class="ln t-dim">empty. try: watch CVE-2026-93616</div>`)}
  else if(/^stack(\s|$)/.test(lc)){const [,sub,...rest]=c.split(' ');const arg=rest.join(' ');
    if(sub==='add'&&arg){arg.split(',').forEach(stackAdd);print(`<div class="ln">stack: ${ST.stack.map(esc).join(', ')}</div><div class="ln t-dim">${rows.filter(inStack).length} CVEs match right now</div>`)}
    else if((sub==='rm'||sub==='remove')&&arg){stackRm(arg.toLowerCase());print(`<div class="ln">removed ${esc(arg)}</div>`)}
    else print(ST.stack.length?`<div class="ln">${ST.stack.map(esc).join(', ')}</div><div class="ln t-dim">${rows.filter(inStack).length} matching CVEs · stack add &lt;name&gt; · stack rm &lt;name&gt;</div>`:`<div class="ln t-dim">no stack yet. try: stack add wordpress, nginx</div>`)}
  else if(/^export(\s|$)/.test(lc)){const kind=lc.includes('json')?'json':'csv';const m=rows.filter(parseQ(c.split(' ').slice(2).join(' ')));exportRows(m,kind);print(`<div class="ln">wrote subzer0-${D.gen.slice(0,10)}.${kind} <span class="t-dim">(${m.length} rows)</span></div>`)}
  else if(lc==='whoami')print(`<div class="ln">user</div>`);
  else if(lc==='date')print(`<div class="ln">${new Date().toUTCString()}</div>`);
  else if(lc==='ls')print(`<div class="ln"><span class="t-ice">snapshot/</span>   <span class="t-ice">shards/</span>   manifest.json   epss.json   kev.json   <span class="t-ok">${CMDS.map(x=>x[0].slice(2)).filter(x=>x!=='clear').join('   ')}</span></div>`);
  else if(lc==='uname -a'||lc==='uname')print(`<div class="ln">SubZer0 tty1 2.0.0-zero #1 SMP ${D.gen.slice(0,10)} static-export web/wasm GNU/Browser</div>`);
  else if(lc==='history')print(hist.map((h,i)=>`<div class="ln"><span class="t-dim">${String(i+1).padStart(4,' ')}</span>  ${esc(h)}</div>`).join(''));
  else if(lc==='banner')print(`<pre class="banner">${BANNER}</pre>`),sizeBanner();
  else if(lc.startsWith('sudo'))print(`<div class="ln"><span class="t-err">user is not in the sudoers file.</span> <span class="t-dim">This incident will be reported.</span></div>`);
  else if(lc==='exit'||lc==='logout')print(`<div class="ln t-dim">nice try.</div>`);
  else print(`<div class="ln">sz-sh: command not found: ${esc(c.split(' ')[0])} <span class="t-dim">try help</span></div>`);
  print(`<div class="ln"> </div>`)}

/* ---------- live: poll the manifest, diff, update in place ---------- */
function nextRun(){const now=Date.now(),d=new Date();for(let k=0;k<2;k++)for(const h of [0,6,12,18]){const t=Date.UTC(d.getUTCFullYear(),d.getUTCMonth(),d.getUTCDate()+k,h,17);if(t>now)return t}return now}
function dur(ms){const s=Math.max(0,Math.floor(ms/1000));return `${Math.floor(s/3600)}h ${String(Math.floor(s%3600/60)).padStart(2,'0')}m ${String(s%60).padStart(2,'0')}s`}
let polling=false,lastPoll=0;
function tick(){const s=dur(nextRun()-Date.now());const n=document.getElementById('nextSync');if(n)n.textContent='next run '+s;const cd=document.getElementById('cd');if(cd)cd.textContent=s;
  if(document.visibilityState==='visible'&&Date.now()-lastPoll>60000)poll()}
async function poll(){if(polling)return;polling=true;lastPoll=Date.now();
  try{const m=await loadManifest();if(m.generated_at===D.gen)return;const old=new Set(rows.map(r=>r.id)),oldK=new Set(rows.filter(r=>r.k).map(r=>r.id));
    const x=await loadAll(m);adopt(x);REC.clear();EPSS=null;
    const fresh=rows.filter(r=>!old.has(r.id)),newK=rows.filter(r=>r.k&&!oldK.has(r.id));
    rerender();announce(fresh,newK);setHealth(true)}
  catch(e){setHealth(false,e.message)}finally{polling=false}}
function setHealth(ok,msg){const l=document.querySelector('.live');if(!l)return;l.classList.toggle('bad',!ok);l.title=ok?'data verified':'last check failed: '+msg}
function rerender(){const keep=[...document.querySelectorAll('.panel')].map(p=>p.scrollTop);briefing();draw();document.querySelectorAll('.panel').forEach((p,i)=>{if(i!==3)p.scrollTop=keep[i]})}
function announce(fresh,newK){if(!fresh.length&&!newK.length)return;const pool=[...newK,...fresh];const pick=pool.sort((a,b)=>a.P[0]-b.P[0]||b.c-a.c)[0];
  const more=fresh.length+newK.length-1;
  if(cur===3&&document.getElementById('to')){print(`<div class="ln"><span class="t-warn">[ LIVE ]</span> ${fresh.length} new, ${newK.length} added to KEV · top: <span class="t-ice" data-cve="${pick.id}" style="cursor:pointer;text-decoration:underline">${pick.id}</span></div>`);return}
  const T=document.getElementById('toast');T.innerHTML=`<div style="display:flex;gap:8px"><span class="chip ice">${newK.includes(pick)?'Now on KEV':'Just in'}</span>${chip(pick.s)}${inStack(pick)?'<span class="chip high">your stack</span>':''}</div><div class="credit-name">${pick.id}</div><div class="t">${pick.T}</div><div class="code" style="margin-top:6px">${more>0?`+${more} more in this update · `:''}tap to open. no refresh needed.</div>`;
  T.dataset.cve=pick.id;T.classList.add('on');clearTimeout(T._t);T._t=setTimeout(()=>T.classList.remove('on'),9000)}
function live(){tick();setInterval(tick,1000);document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')tick()})}

/* ---------- boot ---------- */
function bootError(e){document.getElementById('p0').innerHTML=`<div class="wrap"><div class="empty" style="padding-top:120px"><span class="chip crit">Integrity</span><div class="credit-name" style="font-size:36px;margin:16px 0 10px">Couldn't verify the data</div>SubZer0 won't show anything it can't check. ${esc(e.message)}<br><br><button class="btn primary" id="retry">Try again</button></div></div>`;document.getElementById('retry').onclick=()=>location.reload()}
function route(){const rel=location.pathname.startsWith(BASE.pathname)?location.pathname.slice(BASE.pathname.length):'';const m=rel.match(/^cve\/(CVE-\d{4}-\d{4,})\/?$/i);
  return {tab:Math.max(0,SLUG.indexOf(rel.replace(/\/$/,''))),cve:m?m[1].toUpperCase():null}}
(async()=>{renderNav();const R=route();track.classList.add('dragging');go(R.cve?1:R.tab);
  document.getElementById('p0').innerHTML=`<div class="wrap"><div class="empty" style="padding-top:140px"><div class="code">fetching manifest · checking sha256…</div></div></div>`;
  try{const m=await loadManifest();adopt(await loadAll(m))}catch(e){bootError(e);return}
  briefing();research();dossierTab();terminal();live();
  requestAnimationFrame(()=>track.classList.remove('dragging'));
  if(R.cve){history.replaceState(null,'',routeURL());openSheet(R.cve)}
  addEventListener('resize',renderNav);document.fonts&&document.fonts.ready.then(renderNav);
  if('serviceWorker' in navigator&&location.protocol==='https:')navigator.serviceWorker.register(new URL('sw.js',BASE).href,{scope:BASE.pathname}).catch(()=>{});
})();
