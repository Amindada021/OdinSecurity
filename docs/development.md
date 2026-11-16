# Build and verification

Current version is 0.15.0+15; pubspec.yaml is the version source of truth.
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
- App semantic version + increasing Android build number, e.g. `0.15.0+15`.
- Git tag `v0.15.0` when released.
- `OdinSecurity-v0.15.0.apk`, `OdinSecurity-latest.apk`, with SHA-256 checksums.
- Do not commit signing secrets or keystores.

## Test status

Fixtures have been authored but not executed; Flutter/Android executor unavailable during source preparation.
No live sites have been tested. Validate first with a controlled test lab.

## Remaining before parity

Authenticated crawling is conservative: static HTML anchors, not a JavaScript browser crawler. JSON/form login supports configurable fields and returned bearer token or same-origin cookies; same-origin manual WebView sign-in and cookie import are added; native public-client OAuth/OIDC and refresh source are added, pending provider/device verification; full SPA crawling remains pending. No automated exploitation, live proxy, Intruder, or comprehensive DAST engine is implemented. Manual request inspection supports GET/HEAD only. Active security testing and interception require dedicated Android and controlled lab validation. 

## OAuth provider setup

Register a public native client at the authorized provider with Authorization Code + PKCE, redirect URI `com.odin.odin_security:/oauth2redirect`, and least-privilege scopes. No client secret is required. Explicit HTTPS authorization and token endpoints must share the provider origin, which may differ from the resource origin. OAuth refresh before a scan/crawl persists rotated tokens in secure storage; other tools require explicit refresh if expired. Provider integration and Android redirect behavior must be tested before use.

## Report exports

Open a recorded scan to view findings, severity filters, technology evidence and comparison with the previous record. Comparison is a signal only on shared complete successful routes; identity/scope equivalence is not guaranteed. Save JSON, HTML or PDF through Android's file chooser. HTML and JSON preserve Unicode; PDF uses English technical text and built-in fonts. Report paths may themselves be sensitive; review before sharing. Test all three file types on a real device before release.
