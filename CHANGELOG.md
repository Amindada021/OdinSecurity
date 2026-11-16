# Changelog

## 0.27.0+27
- Added Android CI for static analysis, tests and debug APK artifacts. Device validation remains separate.

## 0.26.0+26
- In-app manual request hold/review with explicit forward/drop and immutable destination/method/Accept.
- Scope and credential-origin validation before review and before send; offline fixtures for approval and scope.

## 0.25.0+25
- Offline GraphQL introspection inventory of root queries, mutations, subscriptions and argument counts, with bounded parsing and fixtures.
- No network requests or operation execution.

## 0.24.0+24
- Local bounded line-based message comparer with additions/removals and changes-only filter.
- Descriptive offline token sample analysis: counts, duplicates, lengths, character frequencies and varying positions; not a cryptographic randomness verdict.
- Hex encoding/decoding and HTML escaping tools; pure offline fixtures.

## 0.23.0+23
- Central scope-filtered session metadata logger for passive scans, manual requests and CORS preflights.
- Project-scoped filtering, response status, timing, size, and explicit clear; no body, headers, credentials or query values logged.
- Bounded logger and scope fixtures; not a browser/system interception proxy.

## 0.22.0+22
- Offline HAR traffic summary: scoped request counts, 4xx/5xx, slow requests, recorded duration and response bytes.
- Filter captured traffic by error or latency; preserve a bounded route inventory and omit request/response payloads, headers and query values.
- Offline HAR traffic fixture; browser metadata is distinguished from live measurements.

## 0.21.0+21
- Import bounded sanitized HAR files using Android's document picker (or paste JSON).
- Explicitly save scoped SPA/HAR route metadata per project, search/filter saved routes, reapply current scope and exclusions on load.
- Open a known read-only route in the request inspector without sending automatically; unknown and mutation-method observations remain inventory-only.
- Route persistence and scope fixtures; device file picker verification pending.

## 0.20.0+20
- Persian and English navigation, form labels and guidance; Persian RTL via Flutter localization delegates.
- Light, dark and system theme; persistent UI preferences with defaults and fallback.
- Technical values, findings and report data retain their original English formatting; localization and widget fixtures.

## 0.19.0+19
- Request inspector with explicit repeat, Accept selection, captured byte count and measured HTTP response time.
- Bounded session-only metadata history and comparable request summary; query values, credential headers and response content not retained in history.
- Enforce scan exclusions and delay; require fresh consent on each send. Unrecognized header values redacted.
- Offline request history, comparison and policy fixtures.

## 0.18.0+18
- Explicit CORS configuration audit for one scoped read-only HTTPS endpoint using a fixed synthetic origin and one unauthenticated OPTIONS preflight.
- Classify advertised policy without replaying requests, accessing data or claiming a confirmed vulnerability.
- Scope, exclusion, authorization and response classification fixtures.

## 0.17.0+17
- Trusted TLS certificate audit for one scoped HTTPS target, with explicit authorization and no HTTP payload or credentials.
- Certificate expiry warnings at 30 and 7 days in passive scan reports; invalid validity period checks.
- Distinguish accepted handshake, rejected handshake and unavailable connection without bypassing certificate validation.
- Offline expiry and scope test fixtures; live/device verification pending.

## 0.16.0+16
- User-led HTTPS browser for rendered SPA route discovery, including Fetch/XHR resource timing metadata and rendered anchors.
- Offline HAR import of scoped routes and HTTP methods; no replay, cookies, headers, bodies or query values retained.
- Route metadata limits, scope/exclusion checks, deduplication and offline fixtures. Android WebView validation pending.

## 0.15.0+15
- Search projects by name or URL, edit project details, and manage multiple exact target URLs.
- Preserve project identity, history and stored identities on edits; scope remains explicit.
- About screen with current version, target editor scope fixtures.

## 0.14.0+14
- Scan report viewer with severity filters, per-page evidence and remediation.
- Local JSON, escaped offline HTML and English technical PDF exports via system file picker.
- Compare observations only on uniquely identified successful and complete shared pages, without claiming a fix.
- Offline report escaping, comparison and PDF generation fixtures; device export verification pending.

## 0.13.0+13
- Registered public-client OAuth2/OIDC authorization-code + PKCE through native AppAuth.
- Encrypted refresh token and expiry metadata; explicit refresh and expiry-aware refresh before scan/crawl.
- Explicit HTTPS provider endpoint configuration and resource-origin binding.
- Android redirect scheme preparation, OAuth model fixtures; Android/provider integration not yet verified.

## 0.12.0+12
- Explicit two-account access-control comparison of one user-selected read-only endpoint.
- Independently validated identities, exact-origin restrictions, scan exclusions, and status-only outcome.
- Failed allowed control stops before the second test; unexpected success is a review signal, not an automatic vulnerability claim.
- Offline comparison and scope fixtures.

## 0.11.0+11
- Persistent per-project scan limits: bounded page count, request delay, and excluded path prefixes.
- Authorization and selected scan policy are checked before the start request.
- Crawler stops on 429, repeated 5xx or rejected authenticated session, and reports the reason.
- Offline policy repository and crawler stop-condition fixtures.

## 0.10.0+10
- Expanded CMS, backend runtime, frontend, server and API technology markers.
- Passive development traceback/profiler, additional cookie attributes, CORS consistency and header observations.
- All checks retain bounded, sanitized evidence with no exploit probes.
- Additional technology and false-positive fixtures.

## 0.9.0+9
- Same-origin, user-driven WebView sign-in for session-cookie websites, including manual OTP.
- Explicit session import into secure identity profile; cookie path constraint and header validation.
- Browser policy and cookie scope test fixtures. Android integration validation pending.

## 0.8.0+8
- Named, isolated authentication identities per project, with legacy vault compatibility.
- Optional protected endpoint and expected content marker; failed verification stops authenticated assessment.
- Profile selection/edit/removal and additional offline tests.
- Pre-cancelled crawls stop before authentication.

## 0.7.0+7
- Explicit scoped GET/HEAD request inspector with bounded response display and selected header redaction.
- Android scaffold preparation tool: manifest branding, Internet permission, backup policy and minSdk.
- Build and test handoff; widget, request scope and crawler fixtures. APK generation deferred.

## 0.6.0+6
- Offline Swagger/OpenAPI JSON operation inventory.
- Local Base64, URL, JSON and unverified JWT inspection.
- Import and utility screens and parser unit fixtures.

## 0.5.0+5
- Persistent per-project scan history, capped at 20 records, and copyable sanitized JSON report.
- Original Odin Security shield/monogram vector branding and matching Flutter painter.
- Android vector icon resource ready for manifest wiring after platform generation.
- History round-trip and report fixtures.

## 0.4.0+4
- Bounded same-origin anchor discovery and cancellable read-only page assessment.
- Passive HTTP/TLS scheme, HSTS, CSP, framing, disclosure and cookie attribute observations.
- Findings and per-page status, evidence/remediation; no vulnerability-exploitation claims.
- Offline discovery and security-check fixtures.

## 0.3.0+3
- Secure per-project authentication profile for a selected HTTPS origin.
- Basic, bearer/JWT, explicit cookies, API keys, configurable JSON/form login.
- Token extraction and same-origin credential forwarding; no automatic cross-origin redirects.
- Authentication configuration screen and test fixtures.
- OAuth, browser-assisted/OTP, refresh and multiple test-user profiles remain pending.

## 0.2.0+2
- Persistent project metadata, stable IDs and explicit additional web/API origins.
- Project screen reload and storage-error handling.
- Repository round-trip and duplicate-ID test fixtures.

## 0.1.0+1
- Initial Flutter foundation, exact-origin scope and evidence-based technology identification.

Versioning: semantic version + monotonically increasing Android build number. Use the pubspec as the source of truth. Future APK naming: OdinSecurity-v<version>.apk and OdinSecurity-latest.apk with SHA-256 checksums. Build and release are deferred until requested.
