# Changelog

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
