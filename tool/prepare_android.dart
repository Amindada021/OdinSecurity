import 'dart:io';

/// Run only after flutter create. Does not build or sign the application.
void main() {
  final manifest = File('android/app/src/main/AndroidManifest.xml');
  final gradle = File('android/app/build.gradle.kts');
  final icon = File('android/app/src/main/res/drawable/odin_security_icon.xml');
  if (!manifest.existsSync() || !gradle.existsSync() || !icon.existsSync()) {
    stderr.writeln('Generate the Android scaffold with Flutter and retain the committed vector icon.');
    exitCode = 1;
    return;
  }

  var text = manifest.readAsStringSync();
  if (!text.contains('android.permission.INTERNET')) {
    text = text.replaceFirst('<application', '<uses-permission android:name="android.permission.INTERNET" />\n    <application');
  }
  if (!text.contains('android.permission.ACCESS_NETWORK_STATE')) {
    text = text.replaceFirst('<application', '<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />\n    <application');
  }
  if (!text.contains('.ScheduledCheckService')) {
    text = text.replaceFirst('</application>', '    <service android:name=".ScheduledCheckService" android:exported="true" android:permission="android.permission.BIND_JOB_SERVICE" />\n    </application>');
  }
  text = text.replaceFirst(RegExp(r'android:label="[^"]*"'), 'android:label="Odin Security"');
  text = text.replaceFirst(RegExp(r'android:icon="[^"]*"'), 'android:icon="@drawable/odin_security_icon"');
  if (text.contains('android:allowBackup=')) {
    text = text.replaceFirst(RegExp(r'android:allowBackup="[^"]*"'), 'android:allowBackup="false"');
  } else {
    text = text.replaceFirst('<application', '<application android:allowBackup="false"');
  }
  if (!text.contains('android:icon="@drawable/odin_security_icon"') ||
      !text.contains('android:allowBackup="false"') ||
      !text.contains('android.permission.INTERNET')) {
    throw StateError('Unexpected manifest layout; review before applying changes.');
  }

  var build = gradle.readAsStringSync();
  build = build.replaceFirst(RegExp(r'\bminSdk\s*=\s*flutter\.minSdkVersion'), 'minSdk = 24');
  if (!RegExp(r'\bminSdk\s*=\s*24\b').hasMatch(build)) {
    throw StateError('Expected Android minSdk 24. Review generated Gradle project.');
  }
  if (!build.contains('appAuthRedirectScheme')) {
    if (!build.contains('defaultConfig {')) throw StateError('Missing Android defaultConfig.');
    build = build.replaceFirst('defaultConfig {', 'defaultConfig {\n        manifestPlaceholders.putAll(mapOf("appAuthRedirectScheme" to "com.odin.odin_security"))');
  }
  manifest.writeAsStringSync(text);
  gradle.writeAsStringSync(build);
  stdout.writeln('Android branding, INTERNET permission, secure-storage backup policy and minSdk 24 prepared.');
}
