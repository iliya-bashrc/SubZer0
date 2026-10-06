/* SubZer0 v2 — app.js (modular IIFE, zero deps) */
"use strict";
(() => {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c]));
  const fmt = (n) => Number(n).toLocaleString("en-US");
  const fmtDate = (iso) => iso ? new Date(iso).toLocaleDateString("en-US", { month:"short", day:"numeric", year:"numeric" }) : "—";

  const SEV = { critical:{c:"#ff4d6a",label:"Critical"}, high:{c:"#ff9f43",label:"High"},
                medium:{c:"#ffd166",label:"Medium"}, low:{c:"#6ee7a0",label:"Low"},
                none:{c:"#6b808c",label:"Unrated"} };

  let DB = { records: [], manifest: null, epss: {} };
  // explore state
  const state = { q:"", sev:"all", kev:false, epssMin:0, page:1, per:24 };

  /* ---------- data loading ---------- */
  // Compact index row -> pseudo-record for list rendering. Detail is loaded lazily from shards.
  function rowToRecord(row) {
    return { id: row[0], title: row[1], sev: row[2], score: row[3], kev: !!row[4],
             epss: row[5] != null ? row[5] : null, activity_at: row[6], published: row[7],
             products: row[8] || "" };
  }
  async function loadData() {
    const [m, idx, ep, chg] = await Promise.all([
      fetch("snapshot/manifest.json").then(r => r.json()),
      fetch("snapshot/data/search_index.json").then(r => r.json()),
      fetch("snapshot/data/epss.json").then(r => r.json()).catch(() => null),
      fetch("snapshot/changes.json").then(r => r.json()).catch(() => null),
    ]);
    DB.changes = (chg && chg.events) || [];
    DB.manifest = m;
    DB.index = idx;                       // 15,316 compact rows (~2.7 MB)
    DB.epss = (ep && ep.scores) || {};
    DB.records = idx.map(rowToRecord);    // light records for UI
    DB.records.sort((a,b) => (b.activity_at||"").localeCompare(a.activity_at||""));
    DB.shardMap = await fetch("snapshot/data/shard_map.json").then(r => r.json()).catch(() => ({}));
  }
  const shardCache = {};
  async function loadRecord(cveId) {
    const day = DB.shardMap && DB.shardMap[cveId];
    if (!day) return null;
    if (!shardCache[day]) {
      shardCache[day] = fetch(`snapshot/data/${day}.json`).then(r => r.json());
    }
    const rows = await shardCache[day];
    return rows.find(r => r.id === cveId) || null;
  }

  /* ---------- URL state ---------- */
  function applyUrlState() {
    const u = new URL(location.href);
    const page = u.searchParams.get("page");
    if (page && document.getElementById("page-" + page)) navigateTo(page);
    const q = u.searchParams.get("q");
    if (q != null) { state.q = q; const s = $("#search"); if (s) s.value = q; renderExplore(); }
    const sev = u.searchParams.get("severity");
    if (sev && document.querySelector(`[data-sev="${sev}"]`)) {
      state.sev = sev;
      document.querySelectorAll(".sev-tab").forEach(t => t.classList.toggle("on", t.dataset.sev === sev));
      renderExplore();
    }
    if (u.searchParams.get("kev") === "1") { state.kev = true; $("#kev-only").checked = true; renderExplore(); }
    window.addEventListener("popstate", () => {
      const u2 = new URL(location.href);
      const p2 = u2.searchParams.get("page") || "overview";
      if (!document.getElementById("page-" + p2)) { window.location.reload(); return; }
      document.querySelectorAll(".page").forEach(pg => {
        const cur = pg.id === "page-" + p2;
        pg.classList.toggle("is-current", cur); pg.hidden = !cur;
        pg.style.transform = ""; pg.style.transition = "";
      });
      document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("is-active", b.dataset.nav === p2));
      const q2 = u2.searchParams.get("q") || "";
      state.q = q2; $("#search").value = q2;
      const sev2 = u2.searchParams.get("severity") || "all";
      state.sev = sev2;
      document.querySelectorAll(".sev-tab").forEach(t => t.classList.toggle("on", t.dataset.sev === sev2));
      state.kev = u2.searchParams.get("kev") === "1";
      $("#kev-only").checked = state.kev;
      renderExplore();
    });
  }
  function updateUrl(params) {
    const u = new URL(location.href);
    for (const [k, v] of Object.entries(params)) {
      if (v == null || v === "" || v === false) u.searchParams.delete(k);
      else u.searchParams.set(k, String(v));
    }
    history.replaceState(null, "", u);
  }

  /* ---------- swipe navigation (touch + mouse) ---------- */
  function bindSwipeNavigation() {
    const main = $("#main");
    if (!main || typeof window.PointerEvent !== "function") return;
    const pageOrder = ["overview", "explore", "kev", "community"];
    const blockedSel = "a[href],button,input,select,textarea,summary,details,[role=button],dialog,.search-wrap,.filters,.record-grid,.pager,#chart,.range,canvas,pre";
    let g = null; // active gesture
    let startX = 0, startY = 0, tracking = false;
    const horizontalRatio = 1.25;

    const pageEl = (n) => document.getElementById("page-" + n);
    const idx = () => pageOrder.indexOf(document.querySelector(".page:not([hidden])").id.replace("page-",""));
    const dest = (dir) => { const i = idx() + dir; return i >= 0 && i < pageOrder.length ? pageEl(pageOrder[i]) : null; };

    function setTransform(el, x) { el.style.transition = "none"; el.style.transform = x === null ? "" : `translate3d(${x}px,0,0)`; }
    function settle(el, targetX, then) {
      el.style.transition = "transform .28s cubic-bezier(.2,.8,.3,1)";
      el.style.transform = targetX === null ? "" : `translate3d(${targetX}px,0,0)`;
      if (then) setTimeout(then, 300);
    }
    function commit(dir) {
      const target = pageOrder[idx() + dir];
      if (!target) { pageEl(pageOrder[idx()])?.style.setProperty("transform",""); return; }
      navigateTo(target);
    }
    function navigateTo(page) {
      g = null; tracking = false;
      document.querySelectorAll(".page").forEach(p => {
        const cur = p.id === "page-" + page;
        p.classList.toggle("is-current", cur); p.hidden = !cur;
        p.style.transform = ""; p.style.transition = ""; p.style.zIndex = "";
      });
      document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("is-active", b.dataset.nav === page));
      window.scrollTo({ top: 0 });
    }

    main.addEventListener("pointerdown", (e) => {
      if (e.button !== 0 && e.pointerType === "mouse") return;
      if (e.target.closest(blockedSel)) return;
      startX = e.clientX; startY = e.clientY; tracking = true;
      try { main.setPointerCapture(e.pointerId); } catch {}
    });
    main.addEventListener("pointermove", (e) => {
      if (!tracking) return;
      const dx = e.clientX - startX, dy = e.clientY - startY;
      if (!g) {
        if (Math.abs(dx) < 24) return;
        if (Math.abs(dy) > Math.abs(dx) / horizontalRatio) { tracking = false; return; }
        const dir = dx < 0 ? 1 : -1;
        const d = dest(dir);
        if (!d) { tracking = false; return; }
        g = { dir, dest: d, cur: pageEl(pageOrder[idx()]) };
        d.hidden = false;
        if (g.dir === 1) g.dest.style.zIndex = -1; else g.cur.style.zIndex = -1;
      }
      const eff = Math.sign(dx) * Math.min(Math.abs(dx) * 0.6, innerWidth * 0.45);
      setTransform(g.dir === 1 ? g.cur : g.cur, eff);
      setTransform(g.dest, eff - Math.sign(dx) * innerWidth);
    });
    function end(e) {
      if (!tracking) return; tracking = false;
      if (!g) return;
      const dx = e.clientX - startX;
      const far = Math.abs(dx) > innerWidth * 0.22 || (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(e.clientY - startY) * 1.5);
      const { cur, dest: d, dir } = g; g = null;
      cur.style.zIndex = ""; d.style.zIndex = "";
      if (far) {
        navigateTo(pageOrder[Math.max(0, Math.min(pageOrder.length-1, idx() + dir))]);
      } else {
        settle(cur, null); d.hidden = true; setTransform(d, null);
      }
    }
    main.addEventListener("pointerup", end);
    main.addEventListener("pointercancel", end);

    // arrow keys too
    document.addEventListener("keydown", (e) => {
      if (/input|textarea|select/i.test(document.activeElement.tagName) || document.querySelector("dialog[open]")) return;
      if (e.key === "ArrowRight") navigateTo(pageOrder[Math.min(idx()+1, pageOrder.length-1)]);
      else if (e.key === "ArrowLeft") navigateTo(pageOrder[Math.max(idx()-1, 0)]);
    });
  }
  function navigateTo(page) {
    document.querySelectorAll(".page").forEach(p => {
      const cur = p.id === "page-" + page;
      p.classList.toggle("is-current", cur); p.hidden = !cur;
      p.style.transform = ""; p.style.transition = "";
    });
    document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("is-active", b.dataset.nav === page));
    const u = new URL(location.href);
    if (u.searchParams.get("page") !== page) {
    u.searchParams.set("page", page);
    history.pushState({ page }, "", u);
    }
    window.scrollTo({ top: 0 });
  }
  // unify: delegate nav clicks to navigateTo
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-nav]");
    if (t) navigateTo(t.dataset.nav);
  });

  /* ---------- record cards ---------- */
  function renderOverview() {
    const m = DB.manifest, t = m.totals || {};
    $("#live-text").textContent = "Snapshot " + fmtDate(m.generated_at);
    $("#kpi-total").textContent = fmt(t.cves);
    $("#kpi-critical").textContent = fmt(t.critical);
    $("#kpi-kev").textContent = fmt(t.known_exploited);
    const scored = DB.records.filter(r => r.epss != null).length;
    $("#kpi-epss").textContent = DB.records.length ? `${Math.round(scored/DB.records.length*100)}%` : "—";
    $("#kpi-epss-note").textContent = `${fmt(scored)} / ${fmt(DB.records.length)} in latest day`;
    $("#activity-sub").textContent = `${fmt(t.cves)} CVEs across ${m.days.length} days · ${m.window.start.slice(0,10)} → ${m.window.end.slice(0,10)}`;
    drawChart(m.days);
    // latest 8
    const list = $("#latest-list");
    list.innerHTML = DB.records.slice(0, 8).map(recHTML).join("");
    list.setAttribute("aria-busy","false");
  }

  /* ---------- chart ---------- */
  let chartGeom = [];
  function drawChart(days) {
    const cv = $("#chart"), dpr = window.devicePixelRatio || 1;
    const W = cv.clientWidth || 1000, H = 220;
    cv.width = W * dpr; cv.height = H * dpr;
    const ctx = cv.getContext("2d"); ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, W, H);
    const pad = { l: 8, r: 8, t: 10, b: 22 };
    const order = ["critical","high","medium","low"];
    const colors = { critical:"#ff4d6a", high:"#ff9f43", medium:"#ffd166", low:"#3d5a63" };
    const max = Math.max(1, ...days.map(d => order.reduce((s,k) => s + (d[k]||0), 0) + (d.none||0)+(d.unknown||0)));
    const n = days.length, bw = (W - pad.l - pad.r) / n;
    chartGeom = [];
    // grid lines
    ctx.strokeStyle = "rgba(255,255,255,.06)";
    ctx.fillStyle = "#6b808c"; ctx.font = "10px Inter,sans-serif"; ctx.textAlign = "left";
    for (let i = 1; i <= 3; i++) {
      const y = pad.t + (H - pad.t - pad.b) * i / 4;
      ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y); ctx.stroke();
      ctx.fillText(String(Math.round(max * (4 - i) / 4)), pad.l + 2, y - 3);
    }
    days.forEach((d, i) => {
      const total = order.reduce((s,k) => s + (d[k]||0), 0) + (d.none||0)+(d.unknown||0);
      let y = H - pad.b;
      const segs = [...order.map(k => [k, d[k]||0]), ["low", (d.none||0)+(d.unknown||0)]];
      for (const [k, v] of segs) {
        if (!v) continue;
        const h = (H - pad.t - pad.b) * v / max;
        ctx.fillStyle = k === "low" && (d.none||d.unknown) ? "#31454d" : colors[k];
        const x = pad.l + i * bw + Math.max(1, bw - Math.min(bw - 1, 18));
        const w2 = Math.min(bw - 2, 17);
        roundRect(ctx, x, y - h, w2, h, Math.min(3, w2/2)); ctx.fill();
        y -= h;
      }
      chartGeom.push({ x: pad.l + i * bw, w: bw, d, total });
      // x labels ~ every 6th
      if (i % 6 === 0 || i === n - 1) {
        ctx.fillStyle = "#6b808c"; ctx.font = "10px Inter,sans-serif"; ctx.textAlign = "center";
        ctx.fillText(d.date.slice(5), pad.l + i * bw + bw / 2, H - 6);
      }
    });
  }
  function roundRect(ctx, x, y, w, h, r) {
    r = Math.min(r, h/2, w/2);
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r < 3 ? 0 : r);
    ctx.arcTo(x, y + h, x, y, 0); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  // chart hover tooltip
  const tip = $("#chart-tip");
  $("#chart").addEventListener("mousemove", (e) => {
    const rect = e.target.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const seg = chartGeom.find(g => x >= g.x && x < g.x + g.w);
    if (!seg) { tip.hidden = true; return; }
    const d = seg.d;
    tip.hidden = false;
    tip.style.left = Math.min(e.clientX + 14, window.innerWidth - 170) + "px";
    tip.style.top = (e.clientY + 16) + "px";
    tip.innerHTML = `<b>${d.date}</b><div class="row"><span>Total</span><b>${seg.total}</b></div>` +
      ["critical","high","medium","low"].filter(k => d[k]).map(k =>
        `<div class="row"><span style="color:${SEV[k].c}">${SEV[k].label}</span><span>${d[k]}</span></div>`).join("");
  });
  $("#chart").addEventListener("mouseleave", () => tip.hidden = true);
  window.addEventListener("resize", () => DB.manifest && drawChart(DB.manifest.days));

  /* ---------- record cards ---------- */
  function sevOf(r) { return SEV[r.sev] ? r.sev : "none"; }
  function recHTML(r) {
    const s = sevOf(r);
    const epssTxt = r.epss != null ? `EPSS ${(r.epss*100).toFixed(1)}%` : "";
    return `<li class="rec s-${s}" data-id="${esc(r.id)}">
      <span class="sev-badge" aria-hidden="true"></span>
      <span class="cve-id">${esc(r.id)}</span>
      <span class="cve-meta">${r.score > 0 ? `CVSS ${r.score.toFixed(1)}` : ""}${epssTxt ? " · " + epssTxt : ""} · ${fmtDate(r.activity_at)}</span>
      <span class="cve-title">${esc(r.title || r.desc || "")}</span>
      ${r.kev ? '<span class="tags"><span class="tag kev">🔥 KEV</span></span>' : ""}
    </li>`;
  }

  /* ---------- explore ---------- */
  function buildSevTabs() {
    const counts = { all: DB.records.length };
    for (const r of DB.records) { const s = sevOf(r); counts[s] = (counts[s]||0) + 1; }
    $("#sev-tabs").innerHTML = ["all",...Object.keys(SEV)].map(k =>
      `<button class="sev-tab s-${k==="all"?"none":k} ${k===state.sev?"on":""}" data-sev="${k}">
        ${k!=="all" ? `<i></i>` : ""}${k==="all"?"All":SEV[k].label}<b>${fmt(counts[k]||0)}</b></button>`).join("");
  }
  function filtered() {
    const q = state.q.toLowerCase();
    return DB.records.filter(r => {
      if (state.sev !== "all" && sevOf(r) !== state.sev) return false;
      if (state.kev && !r.kev) return false;
      if (state.epssMin > 0 && (r.epss == null || r.epss*100 < state.epssMin)) return false;
      if (q) {
        const hay = (r.id + " " + (r.title||"") + " " + (r.desc||"") + " " + (r.affected||[]).map(a=>a.vendor+" "+a.product).join(" ")).toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }
  function renderExplore() {
    const items = filtered();
    const pages = Math.max(1, Math.ceil(items.length / state.per));
    state.page = Math.min(state.page, pages);
    const slice = items.slice((state.page-1)*state.per, state.page*state.per);
    $("#explore-count").textContent = fmt(items.length);
    $("#results").innerHTML = slice.length ? slice.map(recHTML).join("")
      : `<div class="panel glass" style="text-align:center;color:var(--dim)">No records match — loosen the filters 🔍</div>`;
    $("#results").setAttribute("aria-busy","false");
    $("#page-info").textContent = `Page ${state.page} / ${pages}`;
    $("#prev").disabled = state.page <= 1;
    $("#next").disabled = state.page >= pages;
  }
  let searchT;
  $("#search").addEventListener("input", (e) => {
    clearTimeout(searchT);
    searchT = setTimeout(() => { state.q = e.target.value; state.page = 1; renderExplore(); updateUrl({ q: state.q }); }, 180);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "/" && !/input|textarea|select/i.test(document.activeElement.tagName)) {
      e.preventDefault(); document.querySelector('[data-nav="explore"]').click(); $("#search").focus();
    }
  });
  $("#sev-tabs").addEventListener("click", (e) => {
    const b = e.target.closest("[data-sev]"); if (!b) return;
    state.sev = b.dataset.sev; state.page = 1;
    document.querySelectorAll(".sev-tab").forEach(t => t.classList.toggle("on", t === b));
    renderExplore(); updateUrl({ severity: state.sev === "all" ? null : state.sev });
  });
  $("#kev-only").addEventListener("change", (e) => { state.kev = e.target.checked; state.page = 1; renderExplore(); updateUrl({ kev: state.kev ? 1 : null }); });
  $("#epss-min").addEventListener("input", (e) => {
    state.epssMin = +e.target.value; $("#epss-val").textContent = state.epssMin; state.page = 1; renderExplore();
  });
  $("#prev").addEventListener("click", () => { state.page--; renderExplore(); window.scrollTo({top:0}); });
  $("#next").addEventListener("click", () => { state.page++; renderExplore(); window.scrollTo({top:0}); });

  /* ---------- Changes page ---------- */
  const CHG_META = {
    new_cve:     { label:"New CVE",    icon:"🆕", color:"#38d6e0" },
    severity:    { label:"CVSS changed", icon:"📈", color:"#ff9f43" },
    epss_jump:   { label:"EPSS jump",  icon:"⚡", color:"#ffd166" },
    kev_added:   { label:"KEV added",  icon:"🔥", color:"#ff4d6a" },
    kev_removed: { label:"KEV removed",icon:"❄️", color:"#6ee7a0" },
  };
  const chgState = { type:"all", page:1, per:30 };
  function renderChanges() {
    if (!DB.changes.length) {
      $("#changes-summary").textContent = "No change history published yet.";
      $("#changes-list").innerHTML = "";
      $("#change-tabs").innerHTML = "";
      return;
    }
    const counts = { all: DB.changes.length };
    for (const e of DB.changes) counts[e.type] = (counts[e.type]||0) + 1;
    $("#change-tabs").innerHTML = ["all",...Object.keys(CHG_META).filter(k => counts[k])].map(k =>
      `<button class="sev-tab ${k===chgState.type?"on":""}" data-chg="${k}">
        ${k==="all" ? "All" : `${CHG_META[k].icon} ${CHG_META[k].label}`}<b>${fmt(counts[k]||0)}</b></button>`).join("");
    $("#changes-summary").textContent = `${fmt(DB.changes.length)} events detected between published snapshots — generated from the real dataset diff, never hand-written.`;
    const items = DB.changes.filter(e => chgState.type === "all" || e.type === chgState.type);
    const pages = Math.max(1, Math.ceil(items.length / chgState.per));
    chgState.page = Math.min(chgState.page, pages);
    const slice = items.slice((chgState.page-1)*chgState.per, chgState.page*chgState.per);
    $("#changes-list").innerHTML = slice.map(e => {
      const meta = CHG_META[e.type] || { label:e.type, icon:"•", color:"#8497a2" };
      let detail = "";
      if (e.type === "new_cve")
        detail = `<span class="tag src">${esc(SEV[e.severity]?.label || "Unrated")}${e.cvss ? " · CVSS " + e.cvss : ""}</span>${e.kev ? '<span class="tag kev">🔥 KEV</span>' : ""}`;
      else if (e.type === "severity")
        detail = `<span class="tag src">${esc(e.from)} → <b style="color:var(--high)">${esc(e.to)}</b> · CVSS ${e.cvss_from} → ${e.cvss_to}</span>`;
      else if (e.type === "epss_jump")
        detail = `<span class="tag src">EPSS ${(e.from*100).toFixed(1)}% → <b style="color:var(--high)">${(e.to*100).toFixed(1)}%</b> ${e.direction === "up" ? "⬆" : "⬇"}</span>`;
      else detail = `<span class="tag src">${esc(e.type)}</span>`;
      return `<div class="rec s-none" data-id="${esc(e.id)}" style="cursor:pointer;--c:${meta.color}">
        <span class="sev-badge" style="background:${meta.color}" aria-hidden="true"></span>
        <span class="cve-id">${esc(e.id)}</span>
        <span class="cve-meta">${meta.icon} ${meta.label}</span>
        <span class="cve-title" style="white-space:normal">${detail}</span>
      </div>`;
    }).join("");
    $("#chg-page-info").textContent = `Page ${chgState.page} / ${pages}`;
    $("#chg-prev").disabled = chgState.page <= 1;
    $("#chg-next").disabled = chgState.page >= pages;
  }
  $("#change-tabs").addEventListener("click", (e) => {
    const b = e.target.closest("[data-chg]"); if (!b) return;
    chgState.type = b.dataset.chg; chgState.page = 1; renderChanges();
  });
  $("#chg-prev").addEventListener("click", () => { chgState.page--; renderChanges(); });
  $("#chg-next").addEventListener("click", () => { chgState.page++; renderChanges(); });

  /* ---------- KEV page ---------- */
  function renderKev() {
    const list = DB.records.filter(r => r.kev);
    $("#kev-list").innerHTML = list.length ? list.map(recHTML).join("")
      : `<div class="panel glass" style="text-align:center;color:var(--dim)">No KEV records in this day shard — the full 40 live in other shards of the archive.</div>`;
    $("#kev-list").setAttribute("aria-busy","false");
  }

  /* ---------- detail modal ---------- */
  function refLabel(url, label) {
    if (label && !/^(reference|refs?)$/i.test(label)) return label;
    try {
      const h = new URL(url).hostname.replace(/^www\./, "");
      if (/nvd\.nist\.gov/.test(h)) return "NVD Record";
      if (/cve\.org/.test(h)) return "CVE Program";
      if (/github\.com\/advisories/.test(h)) return "GitHub Advisory";
      if (/github\.com/.test(h)) return "GitHub";
      if (/cisa\.gov/.test(h)) return "CISA";
      if (/first\.org/.test(h)) return "FIRST EPSS";
      return h;
    } catch { return "Reference"; }
  }
  function affectedHTML(r) {
    const list = r.affected || [];
    if (!list.length) return "";
    return `<h4 class="d-h">Affected products</h4><ul class="d-list">` + list.map(a =>
      `<li><b>${esc(a.vendor || "—")}</b> ${esc(a.product || "")}
        ${a.versions ? `<span class="d-dim">· versions ${esc(String(a.versions))}</span>` : ""}
        ${a.cpe ? `<code class="d-cpe">${esc(a.cpe)}</code>` : ""}
        <span class="d-dim">· ${esc(a.source || "")}</span></li>`).join("") + `</ul>`;
  }
  function timelineHTML(r) {
    const rows = [];
    if (r.published) rows.push(["Published", r.published]);
    if (r.modified && r.modified !== r.published) rows.push(["Last modified", r.modified]);
    if (r.kev && r.kev.dateAdded) rows.push(["Added to CISA KEV", r.kev.dateAdded]);
    if (!rows.length) return "";
    return `<h4 class="d-h">Timeline</h4><ul class="d-list">` + rows.map(([k,v]) =>
      `<li><span class="d-dim">${k}</span> · ${esc(fmtDate(v))}</li>`).join("") + `</ul>`;
  }
  document.addEventListener("click", async (e) => {
    const card = e.target.closest("[data-id]");
    if (!card) return;
    const cveId = card.dataset.id;
    const light = DB.records.find(x => x.id === cveId);
    if (!light) return;
    const d = $("#detail"), s = sevOf(light);
    d.innerHTML = `
      <button class="d-close" aria-label="Close">✕</button>
      <h3>${esc(cveId)}</h3>
      <div class="d-meta">
        <span class="tag s-${s}" style="color:${SEV[s].c};border-color:${SEV[s].c}">${SEV[s].label}${light.score>0 ? " · CVSS " + Number(light.score).toFixed(1) : ""}</span>
        ${light.epss != null ? `<span class="tag src">EPSS ${(light.epss*100).toFixed(1)}%</span>` : ""}
        ${light.kev ? '<span class="tag kev">🔥 CISA KEV</span>' : ""}
        <span class="tag src">Published ${fmtDate(light.published)}</span>
      </div>
      <div class="d-desc" id="d-desc-live">${esc(light.title || "Loading full record…")}</div>
      <p class="d-dim" id="d-loading" role="status" aria-live="polite">Loading full evidence from the snapshot shard…</p>
      <div class="d-refs" id="d-refs"></div>`;
    d.showModal();
    d.querySelector(".d-close").onclick = () => d.close();
    d.onclick = (ev) => { if (ev.target === d) d.close(); };
    // lazy full record
    try {
      const full = await loadRecord(cveId) || {};
      const merged = { ...light, ...full, epss: light.epss };
      const desc = full.desc || full.title || light.title || "No description available.";
      d.querySelector("#d-desc-live").textContent = desc;
      const load = d.querySelector("#d-loading"); if (load) load.remove();
      const refsBox = d.querySelector("#d-refs");
      const seen = new Set();
      const links = [];
      if (full.primary_url) { links.push([full.primary_url, "Open primary source"]); seen.add(full.primary_url); }
      for (const x of (full.refs || [])) if (x && x.url && !seen.has(x.url)) { seen.add(x.url); links.push([x.url, refLabel(x.url, x.label)]); }
      for (const a of (full.advisories || [])) if (a && a.url && !seen.has(a.url)) { seen.add(a.url); links.push([a.url, refLabel(a.url, a.label)]); }
      const kevUrl = full.kev ? "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" : null;
      if (kevUrl && !seen.has(kevUrl)) links.push([kevUrl, "CISA KEV Catalog"]);
      refsBox.innerHTML =
        affectedHTML(merged) + timelineHTML(merged) +
        (links.length ? `<h4 class="d-h">References</h4><div class="d-refrow">` +
          links.slice(0,8).map(([u,l]) => `<a class="btn btn-ghost" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(l)} ↗</a>`).join("") + `</div>` : "");
    } catch (err) { console.warn("detail load failed", err); }
  });

  /* ---------- community terminal typing ---------- */
  function typeTerminal() {
    const el = $("#typed"), out = $("#term-out");
    const cmd = "cat subzer0.info";
    let i = 0;
    (function step() {
      if (i <= cmd.length) { el.textContent = cmd.slice(0, i++); setTimeout(step, 55); }
      else setTimeout(() => { out.hidden = false; }, 250);
    })();
  }

  /* ---------- boot ---------- */
  (async () => {
    try {
      await loadData();
      buildSevTabs(); renderOverview(); renderExplore(); renderKev(); renderChanges(); typeTerminal();
      bindSwipeNavigation();
      applyUrlState();
      if ("serviceWorker" in navigator && location.protocol === "https:") {
        navigator.serviceWorker.register("sw.js").catch(() => {});
      }
    } catch (err) {
      console.error(err);
      document.body.insertAdjacentHTML("afterbegin",
        `<div style="background:#3a1020;color:#ffb3c1;padding:12px 20px;text-align:center">Failed to load snapshot data: ${esc(err.message)}</div>`);
    }
  })();
})();
