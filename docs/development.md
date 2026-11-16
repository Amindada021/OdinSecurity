# Build and verification

Current version is 0.11.0+11; pubspec.yaml is the version source of truth.
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
- App semantic version + increasing Android build number, e.g. `0.11.0+11`.
- Git tag `v0.11.0` when released.
- `OdinSecurity-v0.11.0.apk`, `OdinSecurity-latest.apk`, with SHA-256 checksums.
- Do not commit signing secrets or keystores.

## Test status

Fixtures have been authored but not executed; Flutter/Android executor unavailable during source preparation.
No live sites have been tested. Validate first with a controlled test lab.

## Remaining before parity

Authenticated crawling is conservative: static HTML anchors, not a JavaScript browser crawler. JSON/form login supports configurable fields and returned bearer token or same-origin cookies; same-origin manual WebView sign-in and cookie import are added; federated OAuth/OIDC, refresh and full SPA crawling are pending. No automated exploitation, live proxy, Intruder, or comprehensive DAST engine is implemented. Manual request inspection supports GET/HEAD only. Active security testing and interception require dedicated Android and controlled lab validation. 
