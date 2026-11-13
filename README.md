# Cipher Lens

**See what your connection actually is.** Cipher Lens reads the real transport facts of the page you are on - encrypted DNS (DoH), QUIC / HTTP/3, TLS version, cipher suite, key exchange, remote IP and ECH advertisement - and shows them as six colour-coded cards. It can also probe any URL with your own browser and report the same facts for that URL.

No accounts, no analytics, no remote server: everything is measured locally from the browser's own network stack.

## Why

Padlock in the address bar only tells you "TLS, probably". It does not tell you:

- is DNS encrypted, or is your ISP resolver answering (and possibly poisoning) it?
- is this site on HTTP/3 / QUIC, or still on TCP?
- TLS 1.3 or a downgraded TLS 1.2?
- which cipher suite and which key exchange group were negotiated?
- does the server advertise ECH, or is your SNI in the clear?

Cipher Lens answers those, per site, live - **without ever putting Chrome into "started debugging this browser" mode unless you ask for it.**

## Features

- **Six live cards** - DoH, QUIC, ECH, TLS 1.3, TLS 1.2, Protocol (h3 / h2 / http/1.1).
- **Passive by default** - the popup reads ALPN from the renderer and remote IP / HTTP status from `chrome.webRequest`. No debugger, no yellow infobar, nothing hanging off the tab.
- **Optional Deep scan** - one button attaches the DevTools protocol for a few seconds and adds the real TLS version, cipher suite, key exchange and certificate names, then detaches. Chrome's debugging banner is visible only during those seconds.
- **DNS cross-check** - queries DoH resolvers directly by IP (AliDNS 223.5.5.5 / 223.6.6.6, DNSPod 120.53.53.53) and compares their answer with the IP the page really connected to.
- **ECH advertisement** - resolves the `HTTPS` (type 65) record and reports whether the service publishes an ECH config.
- **URL probe** - type any URL; the extension opens a temporary background tab, navigates for real, reads the same metrics, then closes the tab and returns you to the original page. The probe is passive too - no debugger attach.
- **Hover for evidence** - every card has a tooltip with the resolver answers, certificate names, cipher details and the exact decision logic, including where each value came from.
- **English UI, MV3, zero dependencies.**

## Install (unpacked, developer mode)

1. Download or clone this repository.
2. Open `chrome://extensions/` (or `edge://extensions/`).
3. Turn on **Developer mode**.
4. Click **Load unpacked** and select the repository folder.
5. Open any https site and click the Cipher Lens toolbar icon.

Nothing extra is needed for the six cards. Only the **Deep scan** button temporarily asks Chrome for the debugger, and Chrome shows its yellow "started debugging this browser" bar for the 2-5 seconds that scan runs; the extension detaches in a `finally` block, so the banner disappears on its own.

## How detection works

Cipher Lens does not read `Server:` headers or guess from the URL. Every value comes from one of three places: the browser's own network stack (renderer timing API or `chrome.webRequest`, and the DevTools protocol only during a Deep scan), a DNS-over-HTTPS answer fetched by the extension, or a value `chrome.webNavigation` reports. The pipeline below is what actually happens for each tab.

### 1. Navigation hooks (passive)

`chrome.webNavigation` drives the lifecycle and never attaches anything:

| Event | What the extension does |
| --- | --- |
| `onBeforeNavigate` (main frame only) | Seeds a per-tab record with the requested host and scheme, and fires the three DoH lookups in parallel. |
| `onCommitted` | Reads the committed URL. A redirect to a sibling host (bilibili.com -> www.bilibili.com) only swaps the hostname; a cross-origin hop (uih.feishu.cn -> accounts.feishu.cn) wipes the IP/DNS/protocol fields, because the old connection belongs to a different site. |
| `tabs.onRemoved` | Drops the tab's record. |

State lives in a `Map` keyed by tab id and is mirrored into `chrome.storage.session` (memory only) so a service-worker restart does not lose it. Because a suspended MV3 worker can wake up a few milliseconds late, the extension listens on **both** `webRequest.onResponseStarted` and `webRequest.onCompleted` for main-frame responses - whichever event wakes the worker first still lands.

### 2. ALPN - is it QUIC? (passive, renderer)

The content script reads the navigation timing entry of the page it runs in:

```js
performance.getEntriesByType('navigation')[0].nextHopProtocol  // "h3", "h2", "http/1.1"
```

It reports the value on load and 1.2 s later. If the popup finds no protocol for the tab - typical when the extension was installed or reloaded after the page had already loaded - the background injects the same three-line reader with `chrome.scripting.executeScript` and asks again. `h3` proves QUIC, and QUIC always runs TLS 1.3, so on an HTTP/3 site the TLS 1.3 card goes green with no handshake inspection at all (`tlsSource: "quic"`).

### 3. Remote IP and HTTP status (passive, network stack)

`chrome.webRequest.onResponseStarted` / `onCompleted` for `main_frame` hand over exactly three useful fields:

| Field | Used for |
| --- | --- |
| `details.ip` | the IP the browser actually connected to - the value the DoH answer is compared against |
| `details.statusCode` | HTTP status row |
| `details.fromCache` | cache flag; a cached response has no `ip`, and the tooltip says so |

This is the whole reason the extension no longer needs the debugger: the IP was always obtainable here.

### 4. Deep scan - TLS version, cipher, key exchange, SANs (explicit action only)

The TLS parameters are only reachable through the DevTools protocol, so they are behind one button:

1. `chrome.debugger.attach(tab, "1.3")` -> `Network.enable`, `Network.setCacheDisabled`, `Page.enable` + `Page.getFrameTree` (to remember the **main frame id**, so the document is still recognised after a cross-origin redirect), and `Network.setBypassServiceWorker`.
2. A tiny same-origin request is injected with `Runtime.evaluate`, so a fresh handshake happens even if the page itself came from cache:

```js
var i = new Image();
i.src = location.origin + '/favicon.ico?cipherlens=' + Date.now();
fetch(location.origin + '/?cipherlens=' + Date.now(), { cache: 'no-store', credentials: 'omit' });
```

3. The next `Network.responseReceived` for the main document supplies:

| Field | Used for |
| --- | --- |
| `response.protocol` | ALPN cross-check against the renderer value |
| `response.securityDetails.protocol` | TLS version (a `QUIC` value is normalised to TLS 1.3) |
| `response.securityDetails.cipher` | cipher suite, e.g. `AES_256_GCM` |
| `response.securityDetails.keyExchange` | key-exchange group, when the server exposes one |
| `response.securityDetails.sanList` | certificate names (first three) |
| `response.remoteIPAddress` | IP cross-check |

4. The popup polls the tab record for up to 5 s, then the debugger is detached in a `finally` block. That detach is what removes Chrome's banner, so it happens even when the scan fails.

Rules that keep these values honest:

- A **main-document response that is not cached** always wins over subresources; subresources are only used to fill gaps.
- Responses flagged `fromDiskCache`, `fromMemoryCache`, `fromServiceWorker` or `fromPrefetchCache` carry **no** `securityDetails` and **no** `remoteIPAddress`. They are accepted only as fallback, and the tooltip says so.
- `quic` is derived from the final protocol string (`/h3|quic/`), so the six cards can never disagree with each other.
- The **TLS evidence** row always names its own source: *Implied by QUIC*, *CDP securityDetails (Deep scan)*, or *Not read*.

### 5. DNS and DoH cross-check

DoH is queried straight from the extension - no system resolver involved:

- Endpoints are addressed by **literal IP**, so a poisoned or hijacked system resolver cannot redirect the DNS query itself: AliDNS `https://223.5.5.5/resolve`, AliDNS `https://223.6.6.6/resolve`, DNSPod `https://120.53.53.53/dns-query` (JSON API, `accept: application/dns-json`, `cache: no-store`).
- For every host the extension asks for **A**, **AAAA** and **HTTPS (type 65)** records in parallel, with a 5 s timeout per resolver and a 5 min in-memory cache.
- The **DoH card** turns green only when (a) at least one encrypted resolver answered, and (b) the IP the browser really used appears in that answer set (after normalising `::ffff:` forms and case for IPv6). If the answers disagree, the card goes red and the tooltip says the encrypted resolver is unreachable *or* the answers differ - which is exactly the signature of a poisoned resolver, or of CDN steering.
- Private ranges (`10.`, `127.`, `192.168.`, `172.16-31.`, `fe80::`, `fc00::/7`) are called out as "resolved by internal DNS", because they can never match a public DoH answer.
- The **ECH card** reads the same type-65 answer: the service advertises ECH when the `HTTPS` RR contains an `ech=` parameter. Only advertisement is claimed - the browser never tells an extension whether ECH was actually negotiated.

### 6. URL probe (passive)

The probe field performs a **real navigation**, not a `fetch()`:

1. `chrome.tabs.create({ url, active: false })` - a background tab, so the same passive hooks apply as for any normal page.
2. Poll the tab record every 350 ms for up to 18 s, stopping as soon as protocol, remote IP and the DNS verdict are all present (plain HTTP stops as soon as ALPN is known). The debugger is **not** attached, so no banner appears during a probe.
3. Delete the record, keep the result in `chrome.storage.session` as `lastProbe`, and close the tab 400 ms later.

A real navigation is required on purpose: `fetch()` reuses an already-negotiated connection, so an HTTP/2 connection opened for the current page would make every probe report `h2`, and HSTS/redirect behaviour would differ from what a user actually gets. The tab therefore flashes briefly - that is a deliberate trade for correct numbers, and it is documented in the popup tooltip.

### 7. Card decision rules

| Card | Green | Red | Grey / other |
| --- | --- | --- | --- |
| DoH | encrypted resolver answered and its answer contains the real IP | resolver unreachable, or answers differ | `Pending` until both a DNS answer and a remote IP exist |
| QUIC | `h3` in ALPN | `h2` / `http/1.1` | `?` while unknown |
| ECH | `ech=` present in the type-65 RR | no `ech=`, or no type-65 record | - |
| TLS 1.3 | QUIC proved it, or Deep scan read TLS 1.3 | TLS 1.2 or older from a Deep scan | `Unknown` - the version was not read |
| TLS 1.2 | Deep scan read TLS 1.2 (labelled *downgraded*) | TLS 1.3 in use | `Unknown` - the version was not read |
| Protocol | - | - | shows the ALPN string (`H3` / `H2` / `HTTP/1.1`) |

Every card also has a hover panel listing the raw evidence (resolver names, A/AAAA answers, page IP, cipher, key exchange, certificate names, data source) and a plain-language note about what the metric can and cannot prove.

## What each card means

| Card | Green | Red | What it proves |
| --- | --- | --- | --- |
| DoH | Encrypted DNS reachable **and** its answer matches the IP the page used | Encrypted DNS unreachable, or answers disagree | DNS is resolvable over HTTPS and is consistent with the actual connection |
| QUIC | ALPN is `h3` (HTTP/3 over QUIC, UDP 443) | `h2` / `http/1.1` (TCP 443) | the browser really negotiated HTTP/3 |
| ECH | `HTTPS` RR contains an `ech=` parameter | no `ech=` parameter, or the resolver returned no type-65 record | the server *advertises* ECH support |
| TLS 1.3 | QUIC (always TLS 1.3) or a Deep scan that read TLS 1.3 | a Deep scan that read TLS 1.2 or older | the handshake version |
| TLS 1.2 | a Deep scan that read TLS 1.2 (shown as downgraded) | TLS 1.3 in use | the handshake version |
| Protocol | negotiated ALPN | - | h3 / h2 / http/1.1 |

### Honest limits

- **DoH** - browsers do not expose "did this request use DoH" to extensions. The card therefore verifies *reachability of encrypted DNS plus agreement with the real IP*, which is the strongest evidence available. When the system resolver is poisoned, the answers disagree and the card turns red.
- **ECH** - browsers do not expose whether ECH was actually used. The card proves server-side advertisement only.
- **TLS version / cipher** on an `h2` or `http/1.1` site requires the **Deep scan** button, because a browser extension has no passive API for them. While that scan runs, Chrome shows its yellow debugging bar; it is removed automatically when the scan ends. HTTP/3 sites get TLS 1.3 passively, for free.
- **TLS / ALPN / IP** - read from the main-document response. If the response comes from cache or a Service Worker there is no handshake to read; press **Re-check** (it reloads the tab once and re-reads) or use the URL probe.
- **Cached / reused connections** are flagged in the tooltip.
- **URL probe** - a real navigation is required, because `fetch()` reuses connections and would report the wrong protocol. A tab therefore flashes briefly and is closed automatically.

## Permissions

| Permission | Why |
| --- | --- |
| `tabs`, `webNavigation` | know which tab and URL the metrics belong to; detect redirects |
| `webRequest` + host access | read the main-frame response IP, HTTP status and cache flag - the passive replacement for the debugger |
| `scripting` + host access | read ALPN from the page when the content script was injected too late; run URL probes |
| `debugger` | used **only** by the Deep scan button, for a few seconds, to read TLS version / cipher / key exchange / certificate names |
| `storage` | keep the last probe result in session storage only |

## Privacy

No network traffic is generated except DNS-over-HTTPS lookups sent directly to public DoH resolvers, and the page loads you ask for. Nothing is collected, stored remotely, or transmitted to the author. See [PRIVACY.md](PRIVACY.md).

## License

MIT - see [LICENSE](LICENSE).
