# Build and verification

Current version is 0.57.0+58; pubspec.yaml is the version source of truth.
The repo contains Flutter application source, an Android vector icon, and offline test fixtures, but platform scaffolding has not yet been generated or validated by Flutter.

## First local build (Windows PowerShell)

```powershell
flutter create --platforms=android --project-name odin_security --org com.odin --no-pub .
dart run tool/prepare_android.dart
flutter pub get
flutter analyze --no-fatal-infos
flutter test
flutter build apk --debug
```

The preparation script is idempotent and changes only generated Android manifest/Gradle settings. Review it before running. Preserve the application ID after the first install. The debug APK is an install/test artifact, not a production release. Release signing, APK publication and stable upgrade compatibility will be validated before a real release.

For distribution after testing, follow the Odin family convention:
- App semantic version + increasing Android build number, e.g. `0.57.0+58`.
- Git tag `v0.57.0` when released.
- `OdinSecurity-v0.57.0.apk`, `OdinSecurity-latest.apk`, with SHA-256 checksums.
- Do not commit signing secrets or keystores.

## Test status

Fixtures have been authored but not executed; Flutter/Android executor unavailable during source preparation.
No live sites have been tested. Validate first with a controlled test lab.

## Remaining before parity

Authenticated crawling is conservative: static HTML anchors, not a JavaScript browser crawler. JSON/form login supports configurable fields and returned bearer token or same-origin cookies; same-origin manual WebView sign-in and cookie import are added; native public-client OAuth/OIDC and refresh source are added, pending provider/device verification; user-led rendered SPA discovery is now included; automated SPA crawling remains pending. No automated exploitation, live proxy, Intruder, or comprehensive DAST engine is implemented. Manual requests support GET, HEAD and OPTIONS, plus explicit HTTPS staging-only POST/PUT/PATCH/DELETE with per-send consent. JSON/text body (32 KiB) and allowlisted custom headers are ephemeral. Active security testing and interception require dedicated Android and controlled lab validation. 

## OAuth provider setup

Register a public native client at the authorized provider with Authorization Code + PKCE, redirect URI `com.odin.odin_security:/oauth2redirect`, and least-privilege scopes. No client secret is required. Explicit HTTPS authorization and token endpoints must share the provider origin, which may differ from the resource origin. OAuth refresh before a scan/crawl persists rotated tokens in secure storage; other tools require explicit refresh if expired. Provider integration and Android redirect behavior must be tested before use.

## Report exports

Open a recorded scan to view findings, severity filters, technology evidence and comparison with the previous record. Comparison is a signal only on shared complete successful routes; identity/scope equivalence is not guaranteed. Save JSON, HTML or PDF through Android's file chooser. HTML and JSON preserve Unicode; PDF uses English technical text and built-in fonts. Report paths may themselves be sensitive; review before sharing. Test all three file types on a real device before release.

## SPA and HAR inventory

Select a scoped HTTPS target, open Explore rendered SPA, authorize browsing, sign in manually, navigate to pages and tap Capture routes. It reads rendered anchors, form action/method labels, external script URLs and available Fetch/XHR Resource Timing URL metadata only; no method inference, automatic replay, storage inspection or credential extraction. Normal WebView scripts may contact external resources, but only exact project origins and non-excluded route metadata are retained. Browser state is reset on start and on explicit close; validate on device. For existing authorized browser traffic, import sanitized HAR JSON (max 1 MiB) offline. Only method and route URL without query or fragment are retained, maximum 300 unique entries. Route names may be sensitive. The capture inventory is session-local unless explicitly saved from either screen. Saved metadata has a 300-route cap and is filtered against current scope/exclusions; it does not initiate a scan. HAR file picker reads at most 1 MiB; paths can still contain sensitive identifiers. Open known read-only routes in the inspector, which requires fresh consent. Unknown Fetch/XHR methods and mutation verbs remain inventory-only.

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

The in-app inspector offers five independent session-only request tabs, each with its own editor, latest response and bounded metadata history. Switching tabs clears approval; drafts and responses are discarded on close. Only the active tab can send. It holds a single explicit request for review, with exact destination, Accept, identity-use indicator, optional approved header values and JSON/text body. Write methods require separate HTTPS staging confirmation. Inputs are not persisted; changing a setting resets consent. Only plain equivalent read requests are eligible for response metadata comparisons. Forward sends the approved request; Drop sends nothing. It is not a system proxy and cannot intercept other apps or browser TLS traffic. Verify on device before real use.

## Automated validation

Android CI runs on manual dispatch only; it is not triggered by pushes. Run it at the end of a development batch. It installs Flutter stable, generates the Android scaffold, applies the preparation script, resolves dependencies, analyzes, runs tests and builds a debug APK. If every step passes, download the short-lived `OdinSecurity-debug` artifact from the workflow run. This is not a signed release. Device behavior still requires manual verification.

CI keeps analyzer errors and warnings fatal. Informational SDK deprecations are reported but do not block validation; the Material API migration is tracked separately. The committed analyzer options avoid a missing generated flutter_lints include.

## Security regression audit

Review explicitly provided HTTPS URLs paired with expected status codes. Performs at most ten unauthenticated HEAD requests sequentially, obeys project scope, exclusions and configured delay, and stops on cancellation, throttling, server error or transport failure. It never generates URLs, follows redirects, or submits data. HEAD and GET can differ; discrepancies require manual confirmation.

## WebSocket inventory

Import sanitized HAR JSON from the project. WebSocket upgrade HTTP 101 and ws/wss request records are mapped to exact HTTP(S) origins for scope checks; query values, headers and payloads are not retained. If an exporter provides the optional _webSocketMessages array, direction counts are displayed; otherwise frame data is unavailable. This is offline inventory, not a live WebSocket proxy. The separate Live WebSocket tool directly connects to a user-approved WSS endpoint with exact HTTPS scope, no redirects, standard certificate validation, optional same-origin static saved identity, and no automatic application messages. Displays up to 100 message metadata records and an optional latest 4 KiB text preview; stops at 45 seconds or 256 KiB observed. The Dart SDK assembles individual messages before counting, so use only controlled staging endpoints. Optional manual text message composition for an explicitly opted-in isolated staging connection: each send requires separate confirmation, up to 10 messages and 4 KiB UTF-8 per message. No retained payload, automated sends, automatic reconnect, system proxy or interception of other clients' frames.

## Review organizer

Maintain manual sanitized review notes per project with open, resolved or false-positive status. Stored locally as ordinary preferences; never include secrets or customer data. Route queries are rejected and current project scope is checked on load and save. No captured request or response content is stored.

## Crawl job controls

Pause and resume a running crawl between HTTP requests (the current call finishes). The active crawl budget excludes time spent waiting for resume. Stop also cancels a paused job. Navigation away cancels it. These controls are in memory; app restart recovery and parallel jobs are not implemented.

## Custom scan rules

Project-specific allowlisted public header checks (`header|present` or `header|contains|literal`) are applied to successful HTTP responses in the technology scan and linked-page crawler. Up to 20 rules, no code execution or additional requests. Rule failures are informational observations, not vulnerability confirmation, and actual header values are omitted from reports. Do not enter secrets in rules.

## Selected rendered page exploration

After manual browser sign-in and capture, choose up to five known, read-only queryless anchors from the current exact HTTPS origin. The app visits only the explicitly selected URLs with the browser session and collects route metadata. It stops on unexpected main-frame navigation, errors or cancellation; it never submits forms or clicks controls. Normal page scripts may still run. Use staging only and validate on a device; this is not general automatic SPA crawling.

## Additional header policy diagnostics

The normal passive scan and crawler evaluate HSTS validity/lifetime (RFC 6797), explicit shared caching directives on successful requests that actually carry a selected identity (RFC 9111), HTTPS downgrade redirects without following them, and incompatible cookie attributes/prefixes. These are configuration observations only; no header/cookie values or redirect destinations are included in evidence. Shared caching may be intentional for public content.

## Tool handoff and report baselines

Open eligible GET/HEAD metadata routes from Logger in the Inspector; no request is sent automatically, and records with discarded query values cannot be handed off. In a report, select any older project scan as a baseline. The UI shows unique-route status transitions and coverage differences separately from finding comparisons. Different credentials, scope, and scan coverage may explain changes; not proof that a vulnerability was fixed or introduced.

## Native browser traffic observer

The dedicated Android platform view uses WebViewClient.shouldInterceptRequest to observe request metadata only, returns null to leave normal loading unchanged, and keeps at most 200 scoped events. Top-level navigation is blocked outside the selected HTTPS origin wherever Android WebView callbacks permit; browser scripts and subresources may reach other origins but are not captured outside project scope. No headers, bodies, URL query values, status or TLS decryption. This callback does not cover all redirects, service workers and WebSocket traffic. The Dart boundary revalidates scope. On device, verify platform-view rendering, manual login, capture pause/clear and cleanup of this app's WebView session. No system proxy or certificate installation.

## Parsed HTML checks

Successful complete HTML responses are parsed locally for insecure form actions, GET password fields, cross-origin password form destinations, HTTP active subresources and external scripts without integrity metadata. These are observations, not exploitation proof. No form submission or subresource fetch is performed. Anchor discovery uses parsed DOM and a same-origin document base, with the existing scope and path exclusions.

## Rendered crawl waves

Capture rendered anchors, form/script references and Fetch/XHR resource metadata twice per page, separated by 500 ms, with unchanged page validation. The browser includes bounded open shadow roots. Each reviewed wave selects up to five known queryless read-only links; the total attempted page count is limited by project policy and previously attempted paths are excluded. Newly discovered links appear in the next reviewed wave. No automatic clicks, form submission, guessed URLs or unrestricted recursive browsing.

## Local HTTPS tunnel

The explicitly started IPv4 loopback CONNECT listener accepts only the selected HTTPS project's host and port and requires a randomly generated session Basic credential. Configure a compatible test client manually with the displayed port and credentials. Limits: 90 seconds, 12 accepted attempts, three simultaneous peers and 2 MiB relayed per peer. No TLS termination, certificate installation, HTTP forwarding, system proxy changes or request/response logging. Scope is origin-level (the encrypted URL path is not visible); unavailable when path exclusions are configured. Device socket lifecycle and protocol compatibility require validation.

## API response observations

Complete bounded JSON responses are inspected locally for populated internal-secret-like fields, token-like fields and stack trace indicators, plus malformed declared JSON. Findings contain fixed descriptions rather than field values or response body data. These are review signals, not proof of a credential leak; authentication endpoints can legitimately return tokens. No extra requests are sent.

## Session health checks

From a selected saved identity, explicitly authorize Check session. Login and verification requests are rejected before transport if excluded by project policy. Cookie Max-Age is enforced relative to session creation and OAuth expiry is respected on later requests. Authenticated reads no longer silently send without applicable credentials. The dedicated screen reports verification outcome without displaying credentials or response content. Without a configured protected verification marker, it cannot establish session validity.

## OpenAPI contract review

Import existing Swagger 2.x/OpenAPI JSON offline. Classifies operations by inherited or overridden security declarations, detects anonymous options, undeclared or unknown schemes, HTTP server/scheme declarations and missing documented 401/403 for security-required operations. Filters by protection declaration. Contract metadata cannot prove actual access control. No endpoint invocation or remote reference resolution.

## Crawl checkpoint recovery

The crawl saves its bounded observed and pending queryless route queue after each finished attempt. Resume requires fresh approval, the same selected target/profile name and current valid policy. It skips completed routes and preserves the cumulative page budget. An interruption during an in-flight read may repeat that read. History records completed batches separately; an abrupt process death before batch reporting can lose findings collected in that batch, even if its route progress is recovered. No response or credential persistence in checkpoints. Explicitly discard a checkpoint before starting a different crawl.

## Advanced offline sample and traffic analysis

Token samples now show per-position empirical Shannon/min-entropy, adjacent duplicate and difference ratios, and bit balance for hexadecimal samples. These are descriptive statistics, not cryptographic randomness certification. Traffic journal filters combine method, status class, duration, route search, truncation and sort by newest, slowest or largest; raw traffic contents are not captured.

## Offline advisory review

Paste a JSON array of up to 500 advisory entries: `id`, `product`, `source` (HTTPS), `affectedVersions` (explicit numeric version strings). Enter the independently confirmed product/version; exact literal matches are unverified leads only. No feed, version inference, network or automatic vulnerability verdict. Verify ecosystem packages and vendor backports manually.

## Declarative rule packs

Custom scan rules provide import/export of `odin.security.headers.v1` JSON packs. Import can replace or merge only the current editor draft, with duplicate/unsupported rules rejected. Save applies the validated draft to the current project. Packs perform passive header checks only, without executable code or network probes.

## Foreground assessment queue

Select up to three exact registered HTTPS URLs, subject to current exclusions and page cap. Each is assessed once without saved credentials; optional parallel mode runs at most two different origins at once. Starts now or after 1/5/15 minutes with explicit consent while screen is current and app foregrounded. Backgrounding/navigation cancels pending work; an in-flight GET may finish. Stop after rate limits, server errors or failed requests before the next batch. Persist completed responses in scan history if the screen remains open. No recurring jobs, background services or authenticated queue.

## Offline test fixtures

Render up to 20 non-secret synthetic values at a single literal `[VALUE]` marker. Review resulting strings locally; no requests or automated test payloads. Offline lab interaction review generates a random 128-bit hex label and matches user-provided JSON rows with exactly `label`, `protocol` (`dns`, `http`, `https`), and `observedAt` (UTC). No network callback service, injection or source attribution. Matches are correlations, not vulnerability proof.

## Fixed-width bit review

For equally sized, even-length hexadecimal synthetic tokens only: display one-bit frequency, descriptive two-bin Pearson chi-square, per-position bias and adjacent-sample Hamming-change ratio. Within-token transitions exclude sample boundaries. No statistical certification or live token harvesting.
