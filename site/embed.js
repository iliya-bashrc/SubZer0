/* SubZer0 embed: <script src="https://iliya-bashrc.github.io/SubZer0/embed.js" data-n="5" data-theme="dark" async></script>
   Drops a sandboxed iframe with today's patch-now CVEs where the tag is, and keeps its height in sync. */
(function(){
  var s=document.currentScript;if(!s)return;
  var base=s.src.replace(/embed\.js(\?.*)?$/,''),o=new URLSearchParams();
  ['n','theme','q'].forEach(function(k){var v=s.getAttribute('data-'+k);if(v)o.set(k,v)});
  var f=document.createElement('iframe');f.src=base+'widget.html?'+o.toString();f.title='SubZer0 · patch-now CVEs by @RootAccessClub';f.loading='lazy';
  f.setAttribute('sandbox','allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox');f.referrerPolicy='no-referrer';
  f.style.cssText='width:100%;max-width:'+(s.getAttribute('data-width')||'420px')+';height:330px;border:0;display:block;color-scheme:normal';
  s.parentNode.insertBefore(f,s);
  addEventListener('message',function(e){if(e.source===f.contentWindow&&e.data&&e.data.sz==='h'&&e.data.h>0&&e.data.h<2000)f.style.height=e.data.h+'px'});
})();
