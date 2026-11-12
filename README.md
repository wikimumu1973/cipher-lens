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
