# Microsoft Edge Add-ons - store listing copy

## Name
Cipher Lens

## Short description (<= 132 chars)
See the real DoH, QUIC, TLS version, cipher suite and ECH status of any site - measured live from your own browser, not guessed.

## Long description
Cipher Lens shows what your connection actually is, not what the padlock implies.

Six colour-coded cards, per site, measured live from the browser's own network stack:

- DoH - is DNS encrypted, and does the encrypted resolver agree with the IP the page really used?
- QUIC - is this site on HTTP/3 over QUIC (UDP 443) or still on TCP?
- ECH - does the server advertise Encrypted Client Hello via its HTTPS DNS record?
- TLS 1.3 / TLS 1.2 - which handshake version was negotiated?
- Protocol - h3, h2 or http/1.1, from the real ALPN result.

Passive by default: the cards fill in without touching the debugger, so Chrome never shows its "started debugging this browser" bar just because you opened the popup. Only TLS version and cipher suite on h2 sites need one extra click on **Deep scan**, which shows that bar for a few seconds and then removes it automatically. HTTP/3 sites get TLS 1.3 for free, because QUIC always runs TLS 1.3.

Hover any card for the evidence: resolver answers, certificate names, cipher suite, key exchange, where each value came from, and the exact decision logic.

URL probe: type any address and Cipher Lens loads it in a temporary background tab with your own browser, reports the same six metrics for that URL, then closes the tab and returns you to your page. Real navigation is used on purpose - fetch() reuses connections and would report the wrong protocol. The probe is passive too.

Everything is local. No accounts, no analytics, no author server. The only outbound requests are the DNS-over-HTTPS lookups needed to answer the questions above, and the pages you ask it to probe.

Honest limits: browsers do not expose per-request DoH usage or whether ECH was actually used, so Cipher Lens reports encrypted-DNS reachability plus IP agreement, and ECH advertisement. Not guesses.

## Category
Developer tools

## Language
English

## Privacy policy URL
https://github.com/wikimumu1973/cipher-lens/blob/main/PRIVACY.md

## Support URL / homepage
https://github.com/wikimumu1973/cipher-lens

## Assets
- Logo: 300x300 PNG (icons/icon128.png upscaled for store submission)
- Screenshots: 1280x800 PNG, see ../deliverables/cipher-lens/
