# Cipher Lens

A Chrome / Edge extension that shows **how the current page is really being served**: the ALPN protocol (h3 / h2), the remote IP, whether an encrypted DoH resolver returns that same IP, whether the HTTPS DNS record advertises ECH, and - on demand - the TLS version, cipher suite and certificate names.

Passive by default. Chrome shows its "started debugging this browser" banner **only** while a Deep scan runs.

## Install (unpacked)

1. Open `chrome://extensions` (or `edge://extensions`), enable **Developer mode**.
2. **Load unpacked** and pick this folder.
3. Open any https site and click the Cipher Lens icon.

## How it works

Everything below runs locally in the extension. No page content is uploaded.

| # | Signal | Source / API | Notes |
|---|--------|--------------|-------|
| 1 | URL, tab identity | `chrome.tabs` | Which tab the popup reports on |
| 2 | Navigation start / commit | `chrome.webNavigation` | Resets per-tab state on a new document |
| 3 | **Remote IP**, HTTP status, `fromCache`, redirect chain | `chrome.webRequest.onResponseStarted` + `onCompleted` (`main_frame`) | The only passive way to learn the IP the browser actually connected to |
| 4 | **ALPN / HTTP protocol** | Content script: `performance.getEntriesByType('navigation')[0].nextHopProtocol` | `h3` = HTTP/3 over QUIC, `h2`, `http/1.1` |
| 5 | ALPN fallback for pages opened before the extension loaded | `chrome.scripting.executeScript` | Same `nextHopProtocol` read, injected on demand |
| 6 | **TLS version, cipher suite, key exchange, certificate SANs** | `chrome.debugger` → CDP `Network.enable`, then `securityDetails` on the main-frame response | **Deep scan only**; the debugger session is detached in a `finally` block |
| 7 | **DNS answers over DoH** | `fetch()` to DoH JSON endpoints: AliDNS `https://223.5.5.5/resolve`, DNSPod `https://120.53.53.53/dns-query`, AliDNS `https://223.6.6.6/resolve` | Compares resolver answers with signal 3 |
| 8 | **ECH advertisement** | DoH query for type `HTTPS` (65); looks for the `ech=` parameter | Server-side support only - see limits |
| 9 | URL probe | `chrome.tabs.create({active:false})` + signals 3/4/7 | Opens a hidden tab, reports, closes it |

### Decision rules

- **QUIC card** - green when ALPN is `h3`. A `h3` result implies TLS 1.3, so the TLS 1.3 card is filled from that without the debugger.
- **DoH card** - green when the IP from signal 3 appears in the DoH answers from signal 7. "Encrypted resolver: unreachable" when all three endpoints fail.
- **ECH card** - green when the HTTPS RR contains `ech=`. Absent parameter means the record was served without ECH config, not necessarily that ECH is off.
- **TLS cards** - "Unknown" until a Deep scan reads `securityDetails`; the row "TLS evidence" states which path produced the value.

## What the cards can and cannot tell you

- ALPN, remote IP and HTTP status are **measured** facts from the browser itself.
- The DoH card is an **agreement test**, not a resolver audit. It answers "does an encrypted resolver return the IP the browser used?". A mismatch can mean plaintext DNS, but it can equally mean CDN steering, EDNS Client Subnet, geo-DNS or a different resolver. No extension API exposes which resolver - or which transport - the browser actually used.
- ECH is reported as **advertised in DNS**, never as "used". Chrome does not expose whether ECH was negotiated.
- With QUIC, the cipher suite and key exchange are not available; only the implied TLS 1.3.

## Permissions

`tabs`, `webNavigation`, `webRequest`, `scripting`, `debugger` (Deep scan only), `storage`, plus host access to all sites (needed to see the response IP of whatever page you are on).

## Privacy

No telemetry, no accounts, no remote code. DNS lookups go only to the public DoH endpoints listed above. Per-tab state lives in `chrome.storage.session` and disappears with the browser session. See [PRIVACY.md](PRIVACY.md).

## License

MIT.
