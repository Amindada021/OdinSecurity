# Development checkpoint

Phase 1 source provides a Flutter project screen, explicit authorization gate, single-request passive technology fingerprinting, independent technology layers and unit test fixtures. Project state is currently in memory, not persistent. Authentication, crawling, security findings and APK packaging are not implemented yet.

Android platform scaffolding is intentionally pending Flutter SDK validation. With Flutter installed, run in this repository:

```sh
flutter create --platforms=android --project-name odin_security .
flutter pub get
flutter analyze
flutter test
flutter build apk --debug
```

Review the generated Android manifest and ensure the main manifest declares android.permission.INTERNET before a network-enabled APK is delivered. Verify the generated app does not weaken TLS certificate validation. No real-site scans are part of the test suite.

The source was authored without an available Flutter/Android executor, so the commands above have not been executed.
