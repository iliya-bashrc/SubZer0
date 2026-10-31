/* vcheck:start — shared by site/app.js and worker/bot.js (tests/test_versions.py keeps the copies identical). */
const VPRE={dev:0,snapshot:0,alpha:1,a:1,beta:2,b:2,preview:3,pre:3,rc:4,cr:4};
const vtok=v=>(String(v).trim().toLowerCase().replace(/^v(?=\d)/,'').match(/\d+|[a-z]+/g)||[]).map(t=>/^\d+$/.test(t)?+t:t);
function vcmp(a,b){const x=vtok(a),y=vtok(b);let i=0;
  for(;i<x.length&&i<y.length;i++){const p=x[i],q=y[i];if(p===q)continue;const np=typeof p==='number',nq=typeof q==='number';
    if(np&&nq)return p<q?-1:1;if(np)return q in VPRE?1:-1;if(nq)return p in VPRE?-1:1;
    const rp=p in VPRE?VPRE[p]:9,rq=q in VPRE?VPRE[q]:9;if(rp!==rq)return rp<rq?-1:1;return p<q?-1:1}
  const longer=x.length>y.length,rest=(longer?x:y).slice(i),sg=longer?1:-1;if(!rest.length)return 0;
  if(typeof rest[0]==='string')return rest[0] in VPRE?-sg:sg;return rest.some(t=>t!==0)?sg:0}
const vfix=e=>e[5]||(e[3]&&e[4]===0?e[3]:'');
function vhit(v,e){const lo=e[1],li=e[2],hi=e[3],hx=e[4];if(hx===-1)return false;
  if(lo){const c=vcmp(v,lo);if(c<0||(c===0&&!li))return false}if(hi){const c=vcmp(v,hi);if(c>0||(c===0&&!hx))return false}return true}
const VER_RE=/^v?[0-9][0-9a-z.\-_+~]*$/i;
const vnorm=s=>String(s||'').toLowerCase().replace(/_/g,' ').replace(/[^a-z0-9.+ ]/g,' ').replace(/\s+/g,' ').trim();
/* "nginx 1.24.0" -> {words:['nginx'],version:'1.24.0',shards:['n']} */
function vparse(q){let t=vnorm(String(q||'').replace(/@/g,' ')).split(' ').filter(Boolean).filter(w=>w!=='version'&&w!=='ver');
  let version='';if(t.length>1&&VER_RE.test(t[t.length-1])&&(/[.\-]/.test(t[t.length-1])||/^\d+$/.test(t[t.length-1])))version=t.pop().replace(/^v/,'');
  const shards=[...new Set(t.map(w=>/^[a-z]/.test(w)?w[0]:'0'))].slice(0,4);return{words:t,version,shards}}
/* shards: {shardName: shardJSON}. Returns ranked products with affected CVEs for the version (or every range when no version). */
function vcheck(q,shards,max){const P=vparse(q);max=max||6;if(!P.words.length)return{...P,products:[]};const cands=[];
  for(const s of P.shards){const S=shards[s];if(!S)continue;for(const key in S.p){const [ven,pro]=key.split('|'),words=(ven+' '+pro).split(' ');
    if(!P.words.every(w=>words.some(x=>x.startsWith(w))))continue;const j=P.words.join(' ');
    const score=(pro===j||(ven+' '+pro)===j?4:pro.startsWith(j)?3:words.includes(P.words[0])?2:1)*1000-words.length*10+Math.min(9,S.p[key].length/20);
    cands.push({key,ven,pro,score,S})}}
  const seen=new Set();cands.sort((a,b)=>b.score-a.score);
  const products=cands.filter(c=>!seen.has(c.key)&&seen.add(c.key)).slice(0,max).map(({key,ven,pro,S})=>{const by=new Map();let unknown=0,ranged=0;
    for(const e of S.p[key]){const m=S.c[e[0]];if(e[4]===-1){unknown++;continue}ranged++;
      if(P.version&&!vhit(P.version,e))continue;const o=by.get(m[0]);if(!o)by.set(m[0],{id:m[0],sev:m[1],p:m[2],kev:!!m[3],cvss:m[4],title:m[5],ranges:[e],fix:vfix(e)});else{o.ranges.push(e);const f=vfix(e);if(f&&(!o.fix||vcmp(f,o.fix)>0))o.fix=f}}
    const list=[...by.values()].sort((a,b)=>a.p-b.p||b.kev-a.kev||b.cvss-a.cvss);let fix='';for(const c of list)if(c.fix&&(!fix||vcmp(c.fix,fix)>0))fix=c.fix;
    return{key,vendor:ven,product:pro,affected:list,unknown,ranged,fix}});
  return{...P,products}}
const vrange=e=>e[4]===-1?'version not given':e[1]&&e[3]&&e[1]===e[3]&&e[2]&&e[4]?'= '+e[1]:[e[1]?(e[2]?'≥ ':'> ')+e[1]:'',e[3]?(e[4]?'≤ ':'< ')+e[3]:''].filter(Boolean).join(', ');
/* vcheck:end */
