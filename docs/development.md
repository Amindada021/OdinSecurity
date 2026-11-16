# Build and verification

Current version is 0.26.0+26; pubspec.yaml is the version source of truth.
The repo contains Flutter application source, an Android vector icon, and offline test fixtures, but platform scaffolding has not yet been generated or validated by Flutter.

## First local build (Windows PowerShell)

```powershell
flutter create --platforms=android --project-name odin_security --org com.odin --no-pub .
dart run tool/prepare_android.dart
flutter pub get
flutter analyze
flutter test
flutter build apk --debug
```

The preparation script is idempotent and changes only generated Android manifest/Gradle settings. Review it before running. Preserve the application ID after the first install. The debug APK is an install/test artifact, not a production release. Release signing, APK publication and stable upgrade compatibility will be validated before a real release.

For distribution after testing, follow the Odin family convention:
- App semantic version + increasing Android build number, e.g. `0.26.0+26`.
- Git tag `v0.26.0` when released.
- `OdinSecurity-v0.26.0.apk`, `OdinSecurity-latest.apk`, with SHA-256 checksums.
- Do not commit signing secrets or keystores.

## Test status

Fixtures have been authored but not executed; Flutter/Android executor unavailable during source preparation.
No live sites have been tested. Validate first with a controlled test lab.

## Remaining before parity

Authenticated crawling is conservative: static HTML anchors, not a JavaScript browser crawler. JSON/form login supports configurable fields and returned bearer token or same-origin cookies; same-origin manual WebView sign-in and cookie import are added; native public-client OAuth/OIDC and refresh source are added, pending provider/device verification; user-led rendered SPA discovery is now included; automated SPA crawling remains pending. No automated exploitation, live proxy, Intruder, or comprehensive DAST engine is implemented. Manual request inspection supports GET/HEAD only. Active security testing and interception require dedicated Android and controlled lab validation. 

## OAuth provider setup

Register a public native client at the authorized provider with Authorization Code + PKCE, redirect URI `com.odin.odin_security:/oauth2redirect`, and least-privilege scopes. No client secret is required. Explicit HTTPS authorization and token endpoints must share the provider origin, which may differ from the resource origin. OAuth refresh before a scan/crawl persists rotated tokens in secure storage; other tools require explicit refresh if expired. Provider integration and Android redirect behavior must be tested before use.

## Report exports

Open a recorded scan to view findings, severity filters, technology evidence and comparison with the previous record. Comparison is a signal only on shared complete successful routes; identity/scope equivalence is not guaranteed. Save JSON, HTML or PDF through Android's file chooser. HTML and JSON preserve Unicode; PDF uses English technical text and built-in fonts. Report paths may themselves be sensitive; review before sharing. Test all three file types on a real device before release.

## SPA and HAR inventory

Select a scoped HTTPS target, open Explore rendered SPA, authorize browsing, sign in manually, navigate to pages and tap Capture routes. It reads rendered anchors and available Fetch/XHR Resource Timing URL metadata only; no method inference, automatic replay, storage inspection or credential extraction. Normal WebView scripts may contact external resources, but only exact project origins and non-excluded route metadata are retained. Browser state is reset on start and on explicit close; validate on device. For existing authorized browser traffic, import sanitized HAR JSON (max 1 MiB) offline. Only method and route URL without query or fragment are retained, maximum 300 unique entries. Route names may be sensitive. The capture inventory is session-local unless explicitly saved from either screen. Saved metadata has a 300-route cap and is filtered against current scope/exclusions; it does not initiate a scan. HAR file picker reads at most 1 MiB; paths can still contain sensitive identifiers. Open known read-only routes in the inspector, which requires fresh consent. Unknown Fetch/XHR methods and mutation verbs remain inventory-only.

## TLS audit

One explicit, trusted TLS handshake to the chosen HTTPS host/port. No credentials, no HTTP request, no custom CA or certificate bypass. An unsuccessful handshake is not proof of an expired certificate. Passive scans attach expiry observations from already accepted HTTPS responses. Validate against controlled valid, expired and unavailable test endpoints before release. Cipher and protocol enumeration is not implemented.

## CORS configuration review

Choose a known read-only HTTPS endpoint within scope and authorize one OPTIONS preflight. The fixed test origin is a reserved invalid domain; only response policy metadata is classified. No credentials or actual cross-origin GET are sent. Wildcard policies may be legitimate and reflection alone is not proof of private data exposure. Verify expected policy and run only on authorized test environments.

## Request inspector

Explicit GET/HEAD sends and repeat with fresh consent, configurable Accept, scope/exclusions and policy delay. Captured size is capped, timing excludes login and includes HTTP response reading. Session-only history is capped at 20 and omits query values, headers and body; no history is saved on disk. Comparison requires identical route, method, Accept and authentication selection, and excludes query-bearing requests. This is not a system-wide proxy or automated replay engine.

## Language and appearance

The project list settings menu switches Persian/English and light/dark/system theme. Persian uses Flutter's RTL layout. Most static navigation, labels and guidance are localized; technical details, dynamic values and exported reports preserve the original English/HTTP formatting. UI preference changes persist locally. Verify RTL layout and long labels on a real device.

## Offline traffic summary

The HAR import also displays up to 1000 scoped HTTP metadata entries with response status, browser-recorded total duration and body size when available. Filtering errors or requests with recorded time of at least one second is purely diagnostic. No headers, bodies, cookies or query values are retained; traffic data stays in memory, apart from explicitly saved route metadata. No live proxy or replay is implied.

## Traffic logger

The in-memory logger captures only method, sanitized route, status or no-response signal, timing and captured size from Odin's passive scans, manual requests and CORS audit. It limits the process to 200 entries and filters current project scope on display. No credential, authentication exchange, cookie, body or raw headers are logged. It is not live browser or device interception.

## Offline message and sample analysis

Compare sanitized HTTP/text messages locally (up to 300 lines and 65536 characters each) and filter changes. Token sample analysis accepts synthetic/non-secret samples and clears input after successful analysis. Frequency entropy and positional variation are descriptive, not a cryptographic estimate. No network requests or automatic sample capture. Hex and HTML escaping are also local.

## GraphQL inventory

Import sanitized introspection JSON via Offline utilities. The parser lists root query/mutation/subscription names and argument counts; it does not perform introspection or send operations. Limits: 1 MiB input characters and 300 fields. Live GraphQL checks and WebSocket interception remain pending.

## Manual request review

The in-app GET/HEAD inspector holds a single explicit request for review, with exact destination, Accept and identity-use indicator. Forward sends the approved request; Drop sends nothing. It is not a system proxy and cannot intercept other apps or browser TLS traffic. Verify on device before real use.
