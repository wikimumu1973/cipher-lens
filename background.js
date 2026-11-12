/* Cipher Lens - background service worker
 * Data sources:
 *  - TLS version / ALPN (h2/h3) / remote IP / cipher suite: chrome.debugger + CDP Network.responseReceived
 *  - DNS (DoH) consistency, ECH advertisement: AliDNS DoH (223.5.5.5) / DNSPod (120.53.53.53) JSON API
 */
const state = new Map();
const dbg = new Set();
const timers = new Map();
const cache = new Map();
const mainFrame = new Map(); // tabId -> main frame id (identifies the main document across cross-origin redirects)

function log(){ console.log.apply(console, ['[SIG]'].concat([].slice.call(arguments))); }
function get(tabId){ return state.get(tabId) || {}; }
function notify(tabId){ chrome.runtime.sendMessage({ action:'tabUpdate', tabId }).catch(function(){}); }
async function persist(){
  try {
    const o = {};
    state.forEach(function(v,k){ o[k] = v; });
    await chrome.storage.session.set({ tabsO: o });
  } catch(e){}
}
async function put(tabId, patch){
  const m = Object.assign({}, get(tabId), patch, { updated: Date.now() });
  state.set(tabId, m);
  await persist(); notify(tabId);
  return m;
}

/* ---------- DoH ---------- */
const RESOLVERS = [
  { name: 'AliDNS 223.5.5.5', base: 'https://223.5.5.5/resolve', json: true },
  { name: 'DNSPod 120.53.53.53', base: 'https://120.53.53.53/dns-query', json: true },
  { name: 'AliDNS 223.6.6.6', base: 'https://223.6.6.6/resolve', json: true }
];

async function dohOnce(r, host, type){
  const url = r.base + '?name=' + encodeURIComponent(host) + '&type=' + type;
  const ctl = new AbortController();
  const to = setTimeout(function(){ ctl.abort(); }, 5000);
  try {
    const resp = await fetch(url, { headers: { accept: 'application/dns-json' }, cache: 'no-store', signal: ctl.signal });
    clearTimeout(to);
    if (!resp.ok) return null;
    const j = await resp.json();
    if (!j || !j.Answer) return [];
    return j.Answer.map(function(a){ return { type: a.type, data: String(a.data) }; });
  } catch(e){ clearTimeout(to); return null; }
}

async function dohAll(host, type){
  const key = type + '|' + host;
  const hit = cache.get(key);
  if (hit && Date.now() - hit.ts < 300000) return hit.out;
  const out = { answers: [], sources: [], records: [] };
  for (const r of RESOLVERS){
    const ans = await dohOnce(r, host, type);
    if (ans === null) continue;
    out.sources.push(r.name);
    out.records = out.records.concat(ans);
    const wants = type === 'A' ? 1 : (type === 'AAAA' ? 28 : 65);
    for (const a of ans) if (a.type === wants || a.type === 5) out.answers.push(a.data);
  }
  cache.set(key, { ts: Date.now(), out: out });
  return out;
}

function ips(arr){
  const o = [];
  for (const s of arr){
    const clean = String(s).replace(/^"/, '').replace(/"$/, '');
    if (/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/.test(clean)) o.push(clean);
    else if (/^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i.test(clean)) o.push(clean);
  }
  return o;
}

async function enrichDns(tabId, host){
  const [a, aaaa, https] = await Promise.all([dohAll(host,'A'), dohAll(host,'AAAA'), dohAll(host,'HTTPS')]);
  if (get(tabId).hostname !== host) return;
  const v4 = ips(a.answers), v6 = ips(aaaa.answers);
  const rr = https.records.filter(function(x){ return x.type === 65; }).map(function(x){ return x.data; }).join(' ');
  let ech = null;
  if (https.sources.length) ech = /ech\s*=\s*"/i.test(rr) || /ech=/i.test(rr);
  await put(tabId, {
    dohAvailable: a.sources.length > 0,
    dnsA: v4, dnsAAAA: v6, dnsVia: a.sources.join(' / ') || null,
    ech: ech, httpsRR: rr || null,
    dnsQueryOk: a.sources.length > 0
  });
  reconcile(tabId);
  log('dns', host, { a4: v4, a6: v6, ech: ech });
}

function normIp(ip){
  let s = String(ip || '');
  if (s.indexOf('::ffff:') === 0) s = s.slice(7);
  return s.toLowerCase();
}

function reconcile(tabId){
  const s = get(tabId);
  if (!s.remoteIP) return;
  const pool = {};
  (s.dnsA || []).forEach(function(x){ pool[x] = 1; });
  (s.dnsAAAA || []).forEach(function(x){ pool[x.toLowerCase()] = 1; });
  const remote = normIp(s.remoteIP);
  if (!Object.keys(pool).length){
    put(tabId, { doh: null, dohDetail: s.dnsQueryOk === false ? 'DoH query failed (blocked)' : 'Waiting for DNS result' });
    return;
  }
  const hit = !!pool[remote];
  const priv = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/.test(remote) || remote.indexOf(':') >= 0 && /^(fe80|fc|fd)/.test(remote);
  put(tabId, {
    doh: hit,
    dohDetail: priv
      ? 'Private address ' + remote + ' - resolved by internal DNS, not public encrypted DNS'
      : (hit ? 'Matches encrypted DNS answer (' + remote + ')' : 'Differs from encrypted DNS answer (CDN steering or no encrypted DNS)')
  });
}

/* ---------- debugger ---------- */
async function attach(tabId){
  if (dbg.has(tabId)) return true;
  try {
    await chrome.debugger.attach({ tabId: tabId }, '1.3');
    dbg.add(tabId);
    await chrome.debugger.sendCommand({ tabId: tabId }, 'Network.enable', {});
    await chrome.debugger.sendCommand({ tabId: tabId }, 'Network.setCacheDisabled', { cacheDisabled: true });
    try {
      await chrome.debugger.sendCommand({ tabId: tabId }, 'Page.enable', {});
      const ft = await chrome.debugger.sendCommand({ tabId: tabId }, 'Page.getFrameTree', {});
      const fid = ft && ft.frameTree && ft.frameTree.frame && ft.frameTree.frame.id;
      if (fid) mainFrame.set(tabId, fid);
    } catch(e){ log('frameTree failed', tabId, String(e && e.message || e)); }
    try { await chrome.debugger.sendCommand({ tabId: tabId }, 'Network.setBypassServiceWorker', { bypass: true }); } catch(e){}
    log('attached', tabId);
    return true;
  } catch(e){
    log('attach failed', tabId, String(e && e.message || e));
    await put(tabId, { dbgError: 'CDP: ' + String(e && e.message || e) });
    return false;
  }
}
async function detach(tabId){
  const t = timers.get(tabId);
  if (t) { clearTimeout(t); timers.delete(tabId); }
  if (!dbg.has(tabId)) return;
  dbg.delete(tabId);
  try { await chrome.debugger.detach({ tabId: tabId }); } catch(e){}
}
function scheduleDetach(tabId, ms){
  const old = timers.get(tabId);
  if (old) clearTimeout(old);
  timers.set(tabId, setTimeout(function(){ timers.delete(tabId); detach(tabId); }, ms));
}

function sameFamily(a, b){
  if (!a || !b) return false;
  a = String(a).toLowerCase(); b = String(b).toLowerCase();
  return a === b || a.slice(-(b.length + 1)) === '.' + b || b.slice(-(a.length + 1)) === '.' + a;
}

chrome.debugger.onEvent.addListener(function(src, method, p){
  const tabId = src.tabId;
  if (tabId < 0 || method !== 'Network.responseReceived') return;
  const s = get(tabId);
  if (!s.hostname) return;
  let host = '';
  try { host = new URL(p.response.url).hostname; } catch(e){ return; }
  const mf = mainFrame.get(tabId);
  // A main-frame document response must be accepted even when cross-origin
  // (e.g. a login redirect to another host); iframe documents still require same site family.
  const isMain = p.type === 'Document' && (!mf || p.frameId === mf);
  if (!isMain && !sameFamily(host, s.hostname)) return;
  const cached = !!(p.response.fromDiskCache || p.response.fromMemoryCache || p.response.fromServiceWorker || p.response.fromPrefetchCache);
  const proto = String(p.response.protocol || '').toLowerCase();
  const sd = p.response.securityDetails || null;
  const patch = {};

  // Real host after redirects (bilibili.com -> www.bilibili.com, or a cross-origin login hop)
  if (isMain && host !== s.hostname){
    patch.hostname = host;
    if (!sameFamily(host, s.hostname)){
      // Site family changed: recorded TLS/IP belong to the old site and must be dropped
      patch.tls = null; patch.tlsRaw = null; patch.cipher = null; patch.keyExchange = null; patch.san = null;
      patch.protocol = null; patch.quic = null; patch.remoteIP = null; patch.doh = null; patch.dohDetail = null;
      patch.ech = null; patch.httpsRR = null; patch.dnsA = null; patch.dnsAAAA = null; patch.dnsVia = null;
      enrichDns(tabId, host);
    }
  }

  // Cached/Service Worker responses carry no remoteIPAddress and no securityDetails - fallback only
  if (p.response.remoteIPAddress && (!s.remoteIP || (isMain && !cached))) patch.remoteIP = p.response.remoteIPAddress;

  const prefer = isMain && !cached;
  if (p.response.status && (isMain || !s.status)){ patch.status = p.response.status; patch.statusText = p.response.statusText || ''; }
  if (proto && (!s.protocol || prefer)) patch.protocol = proto;
  if (sd && sd.protocol && (!s.tls || prefer)){
    patch.tls = (String(sd.protocol).toUpperCase() === 'QUIC') ? 'TLS 1.3' : sd.protocol;
    patch.tlsRaw = sd.protocol;
  }
  if (sd && sd.cipher && (!s.cipher || prefer)) patch.cipher = sd.cipher;
  if (sd && sd.keyExchange && (!s.keyExchange || prefer)) patch.keyExchange = sd.keyExchange;
  if (sd && sd.sanList && (!s.san || prefer)) patch.san = sd.sanList.slice(0,3).join(', ');
  if (cached && !sd) patch.cachedHit = true;

  if (!Object.keys(patch).length) return;
  const protoFinal = patch.protocol || s.protocol || '';
  if (protoFinal) patch.quic = /h3|quic/.test(protoFinal);
  put(tabId, patch).then(function(){ reconcile(tabId); });
});

/* The main document response may be missed when CDP attaches after the request or when the response
    came from cache/Service Worker. After the page loads, fetch a same-origin image so the browser
    reuses or opens a connection and CDP can observe securityDetails and remoteIPAddress. */
async function probeNetwork(tabId){
  const s = get(tabId);
  if (!s.hostname) return;
  if (s.tls && s.remoteIP) return;
  if (!dbg.has(tabId)){
    const ok = await attach(tabId);
    if (!ok) return;
  }
  try { await chrome.debugger.sendCommand({ tabId: tabId }, 'Network.setBypassServiceWorker', { bypass: true }); } catch(e){}
  const expr = "(function(){try{var t=Date.now();var i=new Image();i.referrerPolicy='no-referrer';i.src=location.origin+'/favicon.ico?probe='+t;var f=function(){try{fetch(location.origin+'/?probe='+t,{cache:'no-store',credentials:'omit'}).catch(function(){})}catch(e){}};f();}catch(e){}})()";
  try {
    await chrome.debugger.sendCommand({ tabId: tabId }, 'Runtime.evaluate', { expression: expr, awaitPromise: false });
    log('probe sent', tabId);
  } catch(e){ log('probe failed', tabId, String(e && e.message || e)); }
}

chrome.debugger.onDetach.addListener(function(src){ if (src.tabId >= 0) dbg.delete(src.tabId); });

/* ---------- navigation ---------- */
chrome.webNavigation.onBeforeNavigate.addListener(function(d){
  if (d.frameId !== 0) return;
  let host = '';
  try { host = new URL(d.url).hostname; } catch(e){ return; }
  state.set(d.tabId, { hostname: host, url: d.url, finalUrl: d.url, scheme: (function(){ try { return new URL(d.url).protocol; } catch(e){ return ''; } })(), status: null, tls:null, protocol:null, quic:null, ech:null, doh:null, remoteIP:null, updated: Date.now() });
  persist(); notify(d.tabId);
  attach(d.tabId);
  enrichDns(d.tabId, host);
  scheduleDetach(d.tabId, 15000);
});

chrome.webNavigation.onCommitted.addListener(function(d){
  if (d.frameId !== 0) return;
  const s = get(d.tabId);
  let host = '';
  try { host = new URL(d.url).hostname; } catch(e){ return; }
  if (!s.hostname) {
    state.set(d.tabId, { hostname: host, url: d.url, updated: Date.now() });
    persist(); notify(d.tabId);
    enrichDns(d.tabId, host);
    return;
  }
  if (host !== s.hostname){
    // The committed document is authoritative: within a family only the hostname changes; cross-origin resets everything
    const patch = { hostname: host, url: d.url, finalUrl: d.url };
    try { patch.scheme = new URL(d.url).protocol; } catch(e){}
    if (!sameFamily(host, s.hostname)){
      patch.tls = null; patch.tlsRaw = null; patch.cipher = null; patch.keyExchange = null; patch.san = null;
      patch.protocol = null; patch.quic = null; patch.remoteIP = null; patch.doh = null; patch.dohDetail = null;
      patch.ech = null; patch.httpsRR = null; patch.dnsA = null; patch.dnsAAAA = null; patch.dnsVia = null;
    }
    put(d.tabId, patch);
    enrichDns(d.tabId, host);
  } else if (s.finalUrl !== d.url){
    // Same host but path/scheme changed (e.g. an http -> https upgrade)
    const p2 = { finalUrl: d.url, url: d.url };
    try { p2.scheme = new URL(d.url).protocol; } catch(e){}
    put(d.tabId, p2);
  }
});

chrome.webNavigation.onCompleted.addListener(function(d){
  if (d.frameId !== 0) return;
  probeNetwork(d.tabId);
  scheduleDetach(d.tabId, 6000);
});

chrome.tabs.onRemoved.addListener(function(tabId){ state.delete(tabId); mainFrame.delete(tabId); persist(); detach(tabId); });

/* ---------- probe an arbitrary URL with the real browser ---------- */
const sleep = function(ms){ return new Promise(function(r){ setTimeout(r, ms); }); };

async function probeUrl(rawUrl){
  let u;
  try { u = new URL(rawUrl); } catch(e){ throw new Error('Invalid URL - include the scheme, e.g. https://'); }
  if (!/^https?:$/.test(u.protocol)) throw new Error('Only http:// and https:// are supported');

  const tab = await chrome.tabs.create({ url: u.href, active: false });
  const tabId = tab.id;
  const t0 = Date.now();
  let s = {};
  while (Date.now() - t0 < 18000){
    await sleep(350);
    try { await chrome.tabs.get(tabId); } catch(e){ break; }   // tab was closed or navigated into a download
    s = get(tabId) || {};
    if (s.dbgError) break;
    if (s.scheme === 'http:' && s.protocol) break;              // plain HTTP: ALPN is enough
    if (s.tls && s.remoteIP && s.doh !== null && s.doh !== undefined) break;
  }
  await sleep(250);
  s = get(tabId) || {};

  const out = Object.assign({}, s);
  out.probeUrl = u.href;
  out.url = u.href;   // keep the requested URL as the origin; finalUrl is the post-redirect address
  out.probeMs = Date.now() - t0;
  if (!s.tls && s.scheme !== 'http:' && !s.dbgError) out.probeWarn = 'TLS handshake not captured (page may trigger a download, or the response arrived before CDP attached)';
  if (!s.hostname){
    try { await chrome.tabs.get(tabId); } catch(e){ out.probeWarn = 'Page did not load normally (download link or blocked)'; }
  }

  try { await detach(tabId); } catch(e){}
  state.delete(tabId);
  await persist();
  setTimeout(function(){ try { chrome.tabs.remove(tabId).catch(function(){}); } catch(e){} }, 400);
  try { await chrome.storage.session.set({ lastProbe: out }); } catch(e){}
  log('probe done', u.href, out.probeMs + 'ms', out.tls, out.protocol);
  return out;
}

/* ---------- messages ---------- */
chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse){
  if (!msg) return;
  if (msg.action === 'getInfo'){
    sendResponse(get(msg.tabId));
    return;
  }
  if (msg.action === 'fromContent' && sender.tab){
    const tabId = sender.tab.id;
    const s = get(tabId);
    const d = msg.data || {};
    if (d.protocol && !s.protocol) put(tabId, { protocol: d.protocol, quic: /h3|quic/.test(d.protocol) });
    return;
  }
  if (msg.action === 'probeUrl'){
    probeUrl(msg.url).then(function(r){ sendResponse({ ok: true, data: r }); })
      .catch(function(e){ sendResponse({ ok: false, error: String(e && e.message || e) }); });
    return true;
  }
  if (msg.action === 'recheck'){
    (async function(){
      const tabId = msg.tabId;
      await detach(tabId);
      await attach(tabId);
      try {
        await chrome.debugger.sendCommand({ tabId: tabId }, 'Page.reload', { ignoreCache: true });
        sendResponse({ ok: true });
      } catch(e){ sendResponse({ ok: false, error: String(e && e.message || e) }); }
    })();
    return true;
  }
});

/* cold-start restore */
(async function(){
  try {
    const r = await chrome.storage.session.get('tabsO');
    if (r && r.tabsO) Object.keys(r.tabsO).forEach(function(k){ state.set(Number(k), r.tabsO[k]); });
  } catch(e){}
})();
log('ready v1.0.0');