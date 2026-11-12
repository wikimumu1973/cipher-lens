function setCard(id, cls, text){
  const c = document.getElementById('c-' + id);
  if (!c) return;
  c.className = 'card ' + (cls || '');
  document.getElementById('v-' + id).textContent = text;
}
function setRow(id, text){
  const e = document.getElementById('d-' + id);
  if (e) e.textContent = (text === undefined || text === null || text === '') ? '-' : text;
}

function render(d, tabUrl){
  d = d || {};
  let host = d.hostname;
  if (!host && tabUrl) { try { host = new URL(tabUrl).hostname; } catch(e){ host = tabUrl; } }
  document.getElementById('hostname').textContent = host || 'Unknown';
  const scheme = d.scheme || ((tabUrl || '').indexOf('https:') === 0 ? 'https:' : (tabUrl ? 'http:' : ''));
  const plain = scheme === 'http:';
  const secure = scheme === 'https:';
  document.getElementById('title').textContent = secure ? '\u{1F512} Secure connection' : (plain ? '\u26A0\uFE0F Plain HTTP (no TLS)' : '\u26A0\uFE0F Not HTTPS');

  const privIp = d.remoteIP && /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|fe80|fc[0-9a-f]|fd[0-9a-f])/i.test(String(d.remoteIP));
  if (privIp) setCard('doh','warn','Internal');
  else if (d.dohAvailable === true) setCard('doh','yes','Available');
  else if (d.dohAvailable === false) setCard('doh','no','Unavailable');
  else setCard('doh','warn','Pending');

  if (d.protocol) setCard('quic', d.quic ? 'yes' : 'no', d.quic ? 'Enabled' : (plain ? 'Disabled (plain)' : 'Disabled'));
  else setCard('quic','warn','Pending');

  if (d.ech === true) setCard('ech','yes','Advertised');
  else if (d.ech === false) setCard('ech','no','Not advertised');
  else setCard('ech','warn','Pending');

  const tls = String(d.tls || '').toUpperCase();
  if (plain){ setCard('tls13','no','No TLS'); setCard('tls12','no','No TLS'); }
  else if (tls.indexOf('1.3') >= 0){ setCard('tls13','yes','In use'); setCard('tls12','','Not used'); }
  else if (tls.indexOf('1.2') >= 0){ setCard('tls13','no','Not used'); setCard('tls12','yes','In use'); }
  else { setCard('tls13','warn','?'); setCard('tls12','warn','?'); }

  const p = d.protocol || '';
  setCard('proto', p ? (d.quic ? 'yes' : '') : 'warn', p ? p.toUpperCase() : '?');

  setRow('status', d.status ? (String(d.status) + (d.statusText ? ' ' + d.statusText : '')) : (plain && d.protocol ? 'Plain response' : ''));
  setRow('final', d.finalUrl && d.finalUrl !== d.url ? d.finalUrl : '');
  setRow('ip', d.remoteIP);
  setRow('doh', (d.dohAvailable === false ? 'DoH resolver unreachable; ' : '') + (d.dohDetail || 'Waiting for DNS comparison'));
  setRow('dns', (d.dnsA && d.dnsA.length) ? d.dnsA.slice(0,3).join(', ') : (d.dohAvailable === false ? 'DoH unavailable' : 'Querying'));
  setRow('via', d.dnsVia);
  setRow('cipher', d.cipher ? (d.cipher + (d.keyExchange ? ' / ' + d.keyExchange : '')) : '');
  setRow('ech', d.ech === true ? 'HTTPS RR contains ech= (server supports ECH)' : (d.ech === false ? 'HTTPS RR has no ech= parameter' : 'Waiting'));
  let ts = d.updated ? new Date(d.updated).toLocaleTimeString() : '';
  if (d.dbgError) ts += ' | ' + d.dbgError;
  else if (!d.tls) ts += ' | TLS handshake not captured (cached or Service Worker response)';
  document.getElementById('ts').textContent = ts;
  buildTips(d, tabUrl);
}

let currentTabId = null;
let currentUrl = '';
let probeMode = false;

const bannerEl = document.getElementById('banner');
function showBanner(html, isErr){ bannerEl.className = 'banner' + (isErr ? ' err' : ''); bannerEl.innerHTML = html; bannerEl.hidden = false; }
function hideBanner(){ bannerEl.hidden = true; bannerEl.textContent = ''; }

async function pickTab(){
  const params = new URLSearchParams(location.search);
  const forced = params.get('tabId');
  if (forced){ try { return await chrome.tabs.get(Number(forced)); } catch(e){ return null; } }
  const list = await chrome.tabs.query({});
  let t = list.find(function(x){ return x.active && /^https?:/.test(x.url || ''); });
  if (t) return t;
  const cand = list.filter(function(x){ return /^https?:/.test(x.url || ''); });
  cand.sort(function(a,b){ return (b.lastAccessed || 0) - (a.lastAccessed || 0); });
  return cand[0] || null;
}

async function load(){
  if (probeMode) return;
  try {
    const tab = await pickTab();
    if (!tab){
      document.getElementById('hostname').textContent = 'No inspectable page in this window (chrome:// pages cannot be inspected)';
      return;
    }
    currentTabId = tab.id; currentUrl = tab.url || '';
    const d = await chrome.runtime.sendMessage({ action:'getInfo', tabId: tab.id }).catch(function(){ return null; });
    render(d, currentUrl);
  } catch(e){
    document.getElementById('hostname').textContent = 'Error: ' + (e && e.message);
  }
}

document.getElementById('recheck').addEventListener('click', async function(){
  if (probeMode){ doProbe(); return; }
  if (currentTabId == null) return;
  document.getElementById('ts').textContent = 'Reloading page...';
  await chrome.runtime.sendMessage({ action:'recheck', tabId: currentTabId }).catch(function(){});
});

chrome.runtime.onMessage.addListener(function(msg){
  if (msg && msg.action === 'tabUpdate' && msg.tabId === currentTabId) load();
});
window.addEventListener('focus', load);
document.addEventListener('DOMContentLoaded', load);
/* ---------- hover detail tooltips ---------- */
const TIPS = {};
const tipEl = document.getElementById('tip');
let tipOwner = null;

function esc(s){
  return String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function tipHtml(title, rows, note){
  let h = '<div class="tt">' + esc(title) + '</div>';
  (rows || []).forEach(function(r){
    if (!r) return;
    h += '<div class="tr"><span>' + esc(r[0]) + '</span><b>' + esc(r[1]) + '</b></div>';
  });
  if (note) h += '<div class="tn">' + esc(note) + '</div>';
  return h;
}
function setTip(id, title, rows, note){ TIPS['c-' + id] = tipHtml(title, rows, note); }

function buildTips(d, tabUrl){
  const a = d.dnsA || [];
  const aaaa = d.dnsAAAA || [];
  const tlsTxt = d.tls || '';
  const proto = d.protocol || '';
  const priv = d.remoteIP && /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|fe80|fc[0-9a-f]|fd[0-9a-f])/i.test(String(d.remoteIP));

  const dohState = priv ? 'Private address, resolved by internal DNS' : (d.dohAvailable === true ? 'Encrypted DNS available' : (d.dohAvailable === false ? 'Encrypted DNS unreachable' : 'Querying'));
  setTip('doh', 'DoH - Encrypted DNS', [
    ['Status', dohState],
    ['Resolvers', d.dnsVia || 'Waiting'],
    ['A records', a.length ? a.slice(0, 3).join(', ') + (a.length > 3 ? ' ... ' + a.length + ' total' : '') : 'none'],
    ['AAAA', aaaa.length ? aaaa.slice(0, 2).join(', ') + (aaaa.length > 2 ? ' ... ' + aaaa.length + ' total' : '') : 'none'],
    ['Page IP', d.remoteIP || 'Not captured'],
    ['IP comparison', d.dohDetail || 'Waiting for DNS comparison']
  ], 'How: the extension calls DNS-over-HTTPS (JSON) endpoints directly by IP (223.5.5.5 etc.), bypassing the system resolver. Chrome never exposes per-request DoH usage to extensions, so this card verifies: encrypted DNS is reachable, and its answers match the IP the page actually connected to.');

  setTip('quic', 'QUIC - HTTP/3', [
    ['ALPN', proto ? proto.toUpperCase() : 'Not captured'],
    ['Is QUIC', d.quic === true ? 'Yes (h3 = HTTP/3 over QUIC)' : (proto ? 'No, over TCP' : 'Not captured')],
    ['Decision basis', d.quic ? 'CDP securityDetails.protocol = QUIC' : 'CDP response.protocol'],
    ['Data source', d.cachedHit ? 'includes cached/reused connection responses' : 'CDP Network.responseReceived']
  ], 'QUIC runs over UDP 443. "Disabled" usually means the site does not deploy HTTP/3 (bilibili and some zhihu edges are h2), or the network blocks UDP 443. Chrome enables QUIC by default - no flags needed.');

  setTip('ech', 'ECH - Encrypted Client Hello', [
    ['Advertised by server', d.ech === true ? 'Yes, HTTPS RR has ech=' : (d.ech === false ? 'No, no ech= parameter' : 'Waiting')],
    ['HTTPS RR', d.httpsRR ? String(d.httpsRR).slice(0, 90) + (String(d.httpsRR).length > 90 ? '…' : '') : 'None (resolver may not return type=65)'],
    ['This handshake', 'Browser does not expose ECH usage']
  ], 'Queries type=65 (HTTPS) records via AliDNS DoH to see whether the server publishes an ECH key. This proves server support only - not that this handshake actually used ECH.');

  const use13 = /1\.3/.test(tlsTxt);
  setTip('tls13', 'TLS 1.3', [
    ['This handshake', tlsTxt ? (use13 ? 'TLS 1.3' : tlsTxt + ' (1.3 not used)') : 'Not captured'],
    ['Cipher suite', d.cipher || 'Not captured'],
    ['Key exchange', d.keyExchange || 'Not captured'],
    ['Certificate names', d.san || 'Not captured'],
    ['QUIC site', d.quic ? 'h3 always uses TLS 1.3' : '—']
  ], 'TLS 1.3 completes in a single RTT and keeps only AEAD cipher suites. If it shows "Not captured", reload the page once.');

  const use12 = /1\.2/.test(tlsTxt);
  setTip('tls12', 'TLS 1.2', [
    ['This handshake', tlsTxt ? (use12 ? 'TLS 1.2 (downgraded)' : tlsTxt + ' (1.2 not used)') : 'Not captured'],
    ['Cipher suite', d.cipher || 'Not captured'],
    ['Key exchange', d.keyExchange || 'Not captured'],
    ['Certificate names', d.san || 'Not captured']
  ], 'Only sites or middleboxes without TLS 1.3 (legacy proxies, intranet gateways) fall back to 1.2.');

  const carrier = d.quic ? 'UDP 443 (QUIC)'
    : (proto === 'h2' ? 'TCP 443 (TLS + HTTP/2)'
    : (proto === 'http/1.1' ? 'TCP 443 (TLS + HTTP/1.1)' : 'Unknown'));
  setTip('proto', 'Protocol - ALPN result', [
    ['ALPN', proto ? proto.toUpperCase() : 'Not captured'],
    ['Transport', carrier],
    ['Multiplexing', (proto === 'h2' || d.quic) ? 'Yes (multiplexed)' : 'No'],
    ['Data source', 'CDP Network.responseReceived']
  ], 'h3 = HTTP/3 over QUIC (UDP); h2 = HTTP/2 over TLS (TCP); http/1.1 = legacy. This is the value the browser engine actually negotiated.');
}

function placeTip(card){
  const html = TIPS[card.id];
  if (!html){ tipEl.style.display = 'none'; tipOwner = null; return; }
  if (tipOwner === card && tipEl.style.display === 'block') return;
  tipEl.innerHTML = html;
  tipEl.style.display = 'block';
  const r = card.getBoundingClientRect();
  const w = tipEl.offsetWidth, h = tipEl.offsetHeight;
  const vw = document.documentElement.clientWidth || window.innerWidth;
  const vh = document.documentElement.clientHeight || window.innerHeight;
  let left = r.left + r.width / 2 - w / 2;
  if (left < 6) left = 6;
  if (left + w > vw - 6) left = vw - w - 6;
  let top = r.bottom + 6;
  if (top + h > vh - 4) top = r.top - h - 6;
  if (top < 4) top = Math.max(4, vh - h - 6); // fall back to bottom-aligned when neither above nor below fits
  tipEl.style.left = Math.round(left) + 'px';
  tipEl.style.top = Math.round(top) + 'px';
  tipOwner = card;
}
function hideTip(){ tipEl.style.display = 'none'; tipOwner = null; }

document.addEventListener('mouseover', function(e){
  const t = e.target;
  const card = t && t.closest ? t.closest('.card') : null;
  if (card){ placeTip(card); return; }
  if (tipOwner && !(t && t.closest && t.closest('#tip'))) hideTip();
});
document.addEventListener('mouseleave', hideTip);
window.addEventListener('blur', hideTip);
/* ---------- probe an arbitrary URL with the real browser ---------- */
async function doProbe(){
  let v = String(document.getElementById('probeUrl').value || '').trim();
  if (!v){ showBanner('Enter a URL, e.g. https://www.zhihu.com/', true); return; }
  if (!/^https?:\/\//i.test(v)) v = 'https://' + v;
  const btn = document.getElementById('probeGo');
  btn.disabled = true;
  showBanner('Probing with this browser: <b>' + esc(v) + '</b> ... (opens a temporary background tab, closed automatically)', false);
  try {
    const r = await chrome.runtime.sendMessage({ action:'probeUrl', url: v });
    if (!r || !r.ok) throw new Error((r && r.error) || 'Probe failed');
    const d = r.data || {};
    probeMode = true;
    currentTabId = null;
    render(d, d.finalUrl || v);
    const ms = d.probeMs ? (d.probeMs / 1000).toFixed(1) + 's' : '?';
    let b = 'Probe target <b>' + esc(d.finalUrl || v) + '</b> - took ' + ms;
    if (d.status) b += ' · HTTP ' + d.status + (d.statusText ? ' ' + esc(d.statusText) : '');
    if (d.probeWarn) b += '<br>' + esc(d.probeWarn);
    b += '<br><a id="backCur">← Back to current tab</a>';
    showBanner(b, false);
    const back = document.getElementById('backCur');
    if (back) back.addEventListener('click', function(){ probeMode = false; hideBanner(); load(); });
  } catch(e){
    showBanner('Probe failed: ' + esc(e && e.message || e), true);
  } finally {
    btn.disabled = false;
  }
}
document.getElementById('probeGo').addEventListener('click', doProbe);
document.getElementById('probeUrl').addEventListener('keydown', function(e){ if (e.key === 'Enter') doProbe(); });