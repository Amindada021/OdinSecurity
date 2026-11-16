# Odin Security

Android-first, project-based web and API security assessment for sites under the user's authorization.

## Product workflow

Create project → add web/API origins → choose authentication → validate session → discover and fingerprint → assess → review evidence → export report.

The technology detector reports multiple independent layers with evidence and confidence: CMS, web frontend, backend runtime/framework, reverse proxy/web server, and API conventions. It must not assume an SPA's JavaScript framework is its backend language. Unknown and conflicting results are valid. No scanner can establish every hidden backend technology remotely.

## Delivery plan

| Phase | Scope | Status |
| --- | --- | --- |
| 01 | Flutter Android foundation, project model, exact-origin scope, technology fingerprints and fixtures | In progress |
| 02 | Local persistent projects, Android secure credential storage, scan history and job lifecycle | Planned |
| 03 | Authentication profiles: none, Basic, bearer/JWT, API key, cookie, form/JSON login, browser-assisted login, OAuth/OIDC, MFA and token refresh | Planned |
| 04 | Same-scope discovery, HTML/SPA exploration, OpenAPI import and authenticated endpoint inventory | Planned |
| 05 | Passive evidence-based security checks, technology-specific adapters and confidence | Planned |
| 06 | Explicitly authorized bounded active checks with non-destructive defaults, request caps, exclusions, cancellation and test fixtures | Planned |
| 07 | Proxy/history, request editor and repeater, controlled differential testing with test accounts | Planned |
| 08 | Reports, severity/evidence/remediation, trends, export, Farsi/English, and Android APK validation | Planned |

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

The first implementation is a deliberately limited foundation, not a Burp Suite parity claim. Android platform scaffolding and the build/test pipeline must be validated with the Flutter SDK.
