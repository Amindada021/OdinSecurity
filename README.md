# Odin Security

Android-first, project-based web and API security assessment for sites under the user's authorization.

## Product workflow

Create project → add web/API origins → choose authentication → validate session → discover and fingerprint → assess → review evidence → export report.

The technology detector reports multiple independent layers with evidence and confidence: CMS, web frontend, backend runtime/framework, reverse proxy/web server, and API conventions. It must not assume an SPA's JavaScript framework is its backend language. Unknown and conflicting results are valid. No scanner can establish every hidden backend technology remotely.

## Delivery plan

| Phase | Scope | Status |
| --- | --- | --- |
| 01 | Flutter Android foundation, project model, exact-origin scope, technology fingerprints and fixtures | Source implemented; Android verification pending |
| 02 | Local persistent projects, Android secure credential storage, scan history and job lifecycle | Partial: persistence/history, searchable editable projects and multiple scoped targets implemented; in-session pause/resume/stop for HTML crawl; persisted checkpoints pending |
| 03 | Authentication profiles: none, Basic, bearer/JWT, API key, cookie, form/JSON login, browser-assisted login, OAuth/OIDC, MFA and token refresh | Partial: secure named identities, manual/form/JSON modes and optional session verification; same-origin browser/OTP source; OAuth public-client/PKCE and refresh source implemented; Android/provider verification pending |
| 04 | Same-scope discovery, HTML/SPA exploration, OpenAPI import and authenticated endpoint inventory | Partial: bounded static HTML, offline OpenAPI/HAR and GraphQL introspection inventory, user-led rendered SPA route, form-action and script destination capture and explicit saved project inventory; explicit user-selected rendered page exploration source; Android validation and unrestricted automated SPA crawl pending |
| 05 | Passive evidence-based security checks, technology-specific adapters and confidence | Partial: expanded framework-specific passive diagnostics and declarative custom header rules, fingerprints and TLS certificate expiry; active adapters pending |
| 06 | Explicitly authorized bounded active checks with non-destructive defaults, request caps, exclusions, cancellation and test fixtures | Partial: configurable read-only scan policy and explicit trusted TLS handshake and single-endpoint CORS preflight review and explicit unauthenticated HEAD regression audit; broader active checks pending |
| 07 | Proxy/history, request editor and repeater, controlled differential testing with test accounts | Partial: GET/HEAD inspector with immutable request review, forward/drop and explicit repeat, bounded session-local request metadata and comparison; offline textual comparer, decoder and descriptive token sample analysis, two-account status comparison; offline HAR traffic status/size/timing analysis and scoped WebSocket handshake/frame-count inventory and bounded session metadata logger for Odin requests; live interception pending |
| 08 | Reports, severity/evidence/remediation, trends, export, Farsi/English, and Android APK validation | Partial: report viewer, locally persisted sanitized review notes and workflow statuses, severity filters, cautious historical comparison, JSON/HTML/PDF export source, vector branding, build preparation; Persian/English navigation and static labels with persistent language/theme; technical details remain English; Android validation pending |

## Technology coverage goals

WordPress, Drupal, Joomla, ASP.NET Core / legacy ASP.NET, PHP / Laravel / Symfony, Python / Django / Flask / FastAPI, Java / Spring, Node.js / Express / NestJS, Ruby on Rails, Go, static sites, Next.js, React, Angular, Vue and other frameworks via extensible signatures. Generic HTTP checks must still work when technology is unknown.

## Design constraints

- Flutter UI; isolated engine interfaces; Kotlin Android integrations for secure storage and optional local proxy.
- Explicit, exact-origin scope; confirm permission before network operations. Cross-origin redirects require independent approval.
- Never store credentials in ordinary project JSON, logs, reports, or source control.
- Never automatically submit destructive operations; production-safe checks by default.
- Fingerprints are observations, not proof of vulnerabilities. Findings need evidence and confidence.
- Test with local/synthetic fixtures before real authorized targets. A scan cannot guarantee complete coverage.

## Development

Current development version: **0.36.0+36**. See [changelog](CHANGELOG.md) and [build and validation instructions](docs/development.md). The committed source is a limited assessment foundation, not a Burp Suite parity claim. Unit/widget fixtures are written; Flutter/Android compilation and test execution remain pending. Do not use on production until validated in a controlled lab.
