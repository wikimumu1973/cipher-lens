# Privacy Policy - Cipher Lens

Last updated: 2026-05-20

Cipher Lens is a local diagnostic tool. It has no backend, no account system, no analytics and no advertising.

## What the extension processes

- The URL and hostname of the active tab, to display connection facts for that page.
- Transport metadata of the page's own connection (TLS version, ALPN, cipher suite, key exchange, certificate names, remote IP), read locally from the browser via the DevTools protocol.
- DNS answers returned to the extension's own DNS-over-HTTPS queries.

## Where data goes

Nowhere. All processing happens inside the browser. No data is sent to the extension author or to any third-party service, and no data is sold or shared.

The only outbound requests the extension itself makes are:

1. DNS-over-HTTPS queries to public resolvers (AliDNS `223.5.5.5` / `223.6.6.6`, DNSPod `120.53.53.53`) for the host you are inspecting. These queries contain that hostname, as any DNS query would.
2. The page navigation you explicitly request with the URL probe.

## Storage

The most recent URL-probe result is kept in `chrome.storage.session`, which is memory-only and cleared when the browser closes. No persistent storage, no cookies, no identifiers.

## Permissions justification

- `debugger`: required to read real TLS/ALPN/cipher/remote-IP values; the browser does not expose them through any other API. The debugger attaches only while a page is being measured.
- `tabs`, `webNavigation`: map measured connections to the right tab and follow redirects.
- `storage`: hold the last probe result in memory for the popup.
- `scripting` and host permissions: fallback protocol detection and URL probing on arbitrary sites.

## Children / sensitive data

The extension does not knowingly process personal data, health data, financial data, credentials or communications content. Only transport metadata of the pages you visit is read, and only while the popup is open.

## Changes

Any change to this policy will be published in this repository.

## Contact

Open an issue at https://github.com/wikimumu1973/cipher-lens/issues
