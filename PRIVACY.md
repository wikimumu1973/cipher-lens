# Privacy Policy - Cipher Lens

Last updated: 2026-11-14

Cipher Lens is a local diagnostic tool. It has no backend, no account system, no analytics and no advertising.

## What the extension processes

- The URL and hostname of the active tab, to display connection facts for that page.
- Transport metadata of the page's own connection: ALPN/protocol (h3, h2, http/1.1), remote IP, HTTP status and cache flag from `chrome.webRequest`; DNS answers returned to the extension's own DNS-over-HTTPS queries.
- TLS version, cipher suite, key exchange and certificate names, read via the DevTools protocol **only while you press the Deep scan button**.

## Where data goes

Nowhere. All processing happens inside the browser. No data is sent to the extension author or to any third-party service, and no data is sold or shared.

The only outbound requests the extension itself makes are:

1. DNS-over-HTTPS queries to public resolvers (AliDNS `223.5.5.5` / `223.6.6.6`, DNSPod `120.53.53.53`) for the host you are inspecting. These queries contain that hostname, as any DNS query would.
2. The page navigation you explicitly request with the URL probe.

## Storage

The most recent URL-probe result and the per-tab measurement state are kept in `chrome.storage.session`, which is memory-only and cleared when the browser closes. No persistent storage, no cookies, no identifiers.

## Permissions justification

- `tabs`, `webNavigation`: map measured connections to the right tab and follow redirects.
- `webRequest` (with host access): read the response IP, HTTP status and cache flag of the main frame. This is the passive source of those values - it does not inspect or record request bodies, headers or URLs of subresources beyond matching the tab's main document.
- `scripting` (with host access): read the page's own ALPN value when the content script was injected too late, and run URL probes on arbitrary sites.
- `debugger`: used only by the Deep scan button, for a few seconds, to read TLS version, cipher suite, key exchange and certificate names - the browser exposes them through no other API. The debugger is detached as soon as the scan ends (also on failure), which removes Chrome's debugging banner.
- `storage`: hold the last probe result and per-tab state in memory for the popup.

## Children / sensitive data

The extension does not knowingly process personal data, health data, financial data, credentials or communications content. Only transport metadata of the pages you visit is read.

## Changes

Any change to this policy will be published in this repository.

## Contact

Open an issue at https://github.com/wikimumu1973/cipher-lens/issues
