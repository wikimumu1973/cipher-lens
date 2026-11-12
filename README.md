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

Cipher Lens answers those, per site, live.

## Features

- **Six live cards** - DoH, QUIC, ECH, TLS 1.3, TLS 1.2, Protocol (h3 / h2 / http/1.1).
- **Real handshake data** - TLS version, ALPN, cipher suite, key exchange, certificate SANs and remote IP are read from the browser's actual connection via the DevTools protocol, not guessed from headers.
- **DNS cross-check** - queries DoH resolvers directly by IP (AliDNS 223.5.5.5 / 223.6.6.6, DNSPod 120.53.53.53) and compares their answer with the IP the page really connected to.
- **ECH advertisement** - resolves the `HTTPS` (type 65) record and reports whether the service publishes an ECH config.
- **URL probe** - type any URL; the extension opens a temporary background tab, navigates for real, reads the same metrics, then closes the tab and returns you to the original page.
- **Hover for evidence** - every card has a tooltip with the resolver answers, certificate names, cipher details and the exact decision logic.
- **English UI, MV3, zero dependencies.**

## Install (unpacked, developer mode)

1. Download or clone this repository.
2. Open `chrome://extensions/` (or `edge://extensions/`).
3. Turn on **Developer mode**.
4. Click **Load unpacked** and select the repository folder.
5. Open any https site and click the Cipher Lens toolbar icon.

Chrome shows a yellow "an extension is debugging this browser" bar while the extension reads a handshake. That is expected: the DevTools protocol is the only way an extension can see the real TLS parameters. The debugger detaches a few seconds after the page is loaded.

## How detection works

Cipher Lens does not read `Server:` headers or guess from the URL. Every number it shows comes from one of three places: the browser's own network stack (via the DevTools protocol), a DNS-over-HTTPS answer fetched by the extension, or a value the page reports about itself. The pipeline below is what actually happens for each tab.

### 1. Navigation hooks

`chrome.webNavigation` drives the lifecycle:

| Event | What the extension does |
| --- | --- |
| `onBeforeNavigate` (main frame only) | Seeds a per-tab record with the requested host and scheme, attaches the debugger, and fires the three DoH lookups in parallel. |
| `onCommitted` | Reads the committed URL. A redirect to a sibling host (bilibili.com -> www.bilibili.com) only swaps the hostname; a cross-origin hop (uih.feishu.cn -> accounts.feishu.cn) wipes the TLS/IP/DNS fields, because the old handshake belongs to a different site. |
| `onCompleted` | Runs the fallback connection probe and schedules the debugger detach (6 s later, 15 s at the latest after navigation start). |
| `tabs.onRemoved` | Drops the tab's record and detaches. |

State lives in a `Map` keyed by tab id and is mirrored into `chrome.storage.session` (memory only) so a service-worker restart does not lose it.

### 2. Transport facts (TLS, ALPN, cipher, remote IP)

The extension calls `chrome.debugger.attach(tab, "1.3")` and then, over the DevTools protocol:

1. `Network.enable` - subscribe to `Network.responseReceived`.
2. `Network.setCacheDisabled` and `Network.setBypassServiceWorker` - force a real handshake instead of a cached response.
3. `Page.enable` + `Page.getFrameTree` - remember the **main frame id**, so the main document is still recognised after a cross-origin redirect (iframes are filtered out by site family).

Each `Network.responseReceived` event carries the facts directly:

| Field | Used for |
| --- | --- |
| `response.protocol` | ALPN result: `h3` -> QUIC card green, `h2` / `http/1.1` -> TCP |
| `response.securityDetails.protocol` | TLS version (a `QUIC` value is normalised to TLS 1.3, since QUIC always runs TLS 1.3) |
| `response.securityDetails.cipher` | cipher suite, e.g. `AES_128_GCM` |
| `response.securityDetails.keyExchange` | key-exchange group, when the server exposes one |
| `response.securityDetails.sanList` | certificate names (first three) |
| `response.remoteIPAddress` | the IP the browser actually connected to |
| `response.status` / `statusText` | HTTP status row |

Rules that keep these values honest:

- A **main-document response that is not cached** always wins over subresources; subresources are only used to fill gaps.
- Responses flagged `fromDiskCache`, `fromMemoryCache`, `fromServiceWorker` or `fromPrefetchCache` carry **no** `securityDetails` and **no** `remoteIPAddress`. They are accepted only as fallback, and the tooltip says so.
- `quic` is derived from the final protocol string (`/h3|quic/`), so the six cards can never disagree with each other.

### 3. DNS and DoH cross-check

DoH is queried straight from the extension - no system resolver involved:

- Endpoints are addressed by **literal IP**, so a poisoned or hijacked system resolver cannot redirect the DNS query itself: AliDNS `https://223.5.5.5/resolve`, AliDNS `https://223.6.6.6/resolve`, DNSPod `https://120.53.53.53/dns-query` (JSON API, `accept: application/dns-json`, `cache: no-store`).
- For every host the extension asks for **A**, **AAAA** and **HTTPS (type 65)** records in parallel, with a 5 s timeout per resolver and a 5 min in-memory cache.
- The **DoH card** turns green only when (a) at least one encrypted resolver answered, and (b) the IP the browser really used appears in that answer set (after normalising `::ffff:` forms and case for IPv6). If the answers disagree, the card goes red and the tooltip says the encrypted resolver is unreachable *or* the answers differ - which is exactly the signature of a poisoned resolver, or of CDN steering.
- Private ranges (`10.`, `127.`, `192.168.`, `172.16-31.`, `fe80::`, `fc00::/7`) are called out as "resolved by internal DNS", because they can never match a public DoH answer.
- The **ECH card** reads the same type-65 answer: the service advertises ECH when the `HTTPS` RR contains an `ech=` parameter. Only advertisement is claimed - the browser never tells an extension whether ECH was actually negotiated.

### 4. Fallback probe when the handshake is missed

If the debugger attaches after the document response, or the response came from cache, there is nothing to read. After `onCompleted` the extension then injects a tiny same-origin request via `Runtime.evaluate`:

```js
var i = new Image();
i.src = location.origin + '/favicon.ico?probe=' + Date.now();
fetch(location.origin + '/?probe=' + Date.now(), { cache: 'no-store', credentials: 'omit' });
```

The browser reuses the existing connection or opens a new one, and the resulting `Network.responseReceived` supplies `securityDetails` and `remoteIPAddress`. This is why a value can appear a moment after the page has finished loading, and why the TLS 1.3 tooltip suggests reloading when it shows "Not captured" on a cached page.

### 5. URL probe

The probe field performs a **real navigation**, not a `fetch()`:

1. `chrome.tabs.create({ url, active: false })` - a background tab, so the same navigation hooks and the same measurement path apply as for any normal page.
2. Poll the tab record every 350 ms for up to 18 s, stopping as soon as TLS, remote IP and the DNS verdict are all present (plain HTTP stops as soon as ALPN is known).
3. Detach the debugger, delete the record, keep the result in `chrome.storage.session` as `lastProbe`, and close the tab 400 ms later.

A real navigation is required on purpose: `fetch()` reuses an already-negotiated connection, so an HTTP/2 connection opened for the current page would make every probe report `h2`, and HSTS/redirect behaviour would differ from what a user actually gets. The tab therefore flashes briefly - that is a deliberate trade for correct numbers, and it is documented in the popup tooltip.

### 6. Card decision rules

| Card | Green | Red | Grey / other |
| --- | --- | --- | --- |
| DoH | encrypted resolver answered and its answer contains the real IP | resolver unreachable, or answers differ | `Pending` until both a DNS answer and a remote IP exist |
| QUIC | `h3` in ALPN | `h2` / `http/1.1` | `?` while unknown |
| ECH | `ech=` present in the type-65 RR | no `ech=`, or no type-65 record | - |
| TLS 1.3 | negotiated TLS 1.3 | TLS 1.2 or older | `?` when no handshake was captured |
| TLS 1.2 | negotiated TLS 1.2 (labelled *downgraded*) | TLS 1.3 in use | - |
| Protocol | - | - | shows the ALPN string (`H3` / `H2` / `HTTP/1.1`) |

Every card also has a hover panel listing the raw evidence (resolver names, A/AAAA answers, page IP, cipher, key exchange, certificate names, data source) and a plain-language note about what the metric can and cannot prove.

## What each card means

| Card | Green | Red | What it proves |
| --- | --- | --- | --- |
| DoH | Encrypted DNS reachable **and** its answer matches the IP the page used | Encrypted DNS unreachable, or answers disagree | DNS is resolvable over HTTPS and is consistent with the actual connection |
| QUIC | ALPN is `h3` (HTTP/3 over QUIC, UDP 443) | `h2` / `http/1.1` (TCP 443) | the browser really negotiated HTTP/3 |
| ECH | `HTTPS` RR contains an `ech=` parameter | no `ech=` parameter, or the resolver returned no type-65 record | the server *advertises* ECH support |
| TLS 1.3 | negotiated TLS 1.3 | TLS 1.2 or older | the handshake version |
| TLS 1.2 | negotiated TLS 1.2 (shown as downgraded) | TLS 1.3 in use | the handshake version |
| Protocol | negotiated ALPN | - | h3 / h2 / http/1.1 |

### Honest limits

- **DoH** - browsers do not expose "did this request use DoH" to extensions. The card therefore verifies *reachability of encrypted DNS plus agreement with the real IP*, which is the strongest evidence available. When the system resolver is poisoned, the answers disagree and the card turns red.
- **ECH** - browsers do not expose whether ECH was actually used. The card proves server-side advertisement only.
- **TLS / ALPN / IP** - read from the main-document response. If the response comes from cache or a Service Worker there is no handshake to read; reload the page (or use the URL probe) to capture a fresh one.
- **Cached / reused connections** are flagged in the tooltip.
- **URL probe** - a real navigation is required, because `fetch()` reuses connections and would report the wrong protocol. A tab therefore flashes briefly and is closed automatically.

## Permissions

| Permission | Why |
| --- | --- |
| `debugger` | read TLS / ALPN / cipher / remote IP from the browser's own network stack |
| `tabs`, `webNavigation` | know which tab and URL the metrics belong to; detect redirects |
| `storage` | keep the last probe result in session storage only |
| `scripting` + host access | fallback protocol reading from the page, and probing arbitrary URLs |

## Privacy

No network traffic is generated except DNS-over-HTTPS lookups sent directly to public DoH resolvers, and the page loads you ask for. Nothing is collected, stored remotely, or transmitted to the author. See [PRIVACY.md](PRIVACY.md).

## License

MIT - see [LICENSE](LICENSE).