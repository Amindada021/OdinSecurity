import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/material.dart';
import 'package:odin_security/core/ui_preferences.dart';
import 'package:odin_security/main.dart';
import 'package:odin_security/quick_api_login_dialog.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/scan_policy.dart';
import 'package:odin_security/core/project_storage.dart';
import 'package:odin_security/core/project.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
  testWidgets('automatic scan is default and advanced tools are opt-in', (tester) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    SharedPreferences.setMockInitialValues({});
    final project = SecurityProject(name: 'Example', url: 'https://example.test');
    await tester.pumpWidget(MaterialApp(home: ScanScreen(project: project)));
    await tester.pumpAndSettle();
    expect(find.text('Automatic scan'), findsOneWidget);
    expect(find.text('Start automatic scan'), findsOneWidget);
    final start = tester.widget<FilledButton>(find.ancestor(of: find.text('Start automatic scan'), matching: find.byWidgetPredicate((widget) => widget is FilledButton)));
    expect(start.onPressed, isNull);
    expect(find.text('Representation test matrix'), findsNothing);
    expect(find.text('Public website'), findsOneWidget);
    await tester.tap(find.text('After sign-in'));
    await tester.pumpAndSettle();
    expect(find.text('Sign-in page URL'), findsOneWidget);
    expect(find.text('Open sign-in and scan'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('method.false.false.false')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Use existing credential instead').last);
    await tester.pumpAndSettle();
    expect(find.text('Bearer token'), findsOneWidget);
    final field = tester.widget<TextField>(find.byType(TextField));
    expect(field.obscureText, isTrue);
    await tester.enterText(find.byType(TextField), 'test-token');
    await tester.tap(find.text('Advanced mode'));
    await tester.pumpAndSettle();
    expect(find.text('Representation test matrix'), findsOneWidget);
    expect(find.text('Start automatic scan'), findsNothing);
    await tester.tap(find.text('Automatic scan'));
    await tester.pumpAndSettle();
    expect(find.text('Start automatic scan'), findsOneWidget);
    expect(find.text('Bearer token'), findsNothing);
  });

  testWidgets('explicit separate login origin can be entered without adding project target', (tester) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    SharedPreferences.setMockInitialValues({});
    final project = SecurityProject(name: 'Example', url: 'https://example.test',
        additionalUrls: ['https://api.example.test']);
    await tester.pumpWidget(MaterialApp(home: ScanScreen(project: project)));
    await tester.pumpAndSettle();
    await tester.tap(find.text('After sign-in'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byType(TextField), 'https://panel.example.test/login');
    await tester.pumpAndSettle();
    final consent = find.text('I am authorized to access the sign-in site and assess the selected target.');
    await tester.ensureVisible(consent);
    await tester.tap(consent);
    await tester.pumpAndSettle();
    final button = find.ancestor(of: find.text('Open sign-in and scan'),
      matching: find.byWidgetPredicate((widget) => widget is FilledButton));
    expect(tester.widget<FilledButton>(button).onPressed, isNotNull);
    expect(project.targets.length, 2);
    await tester.enterText(find.byType(TextField), 'http://panel.example.test/login');
    await tester.pumpAndSettle();
    expect(find.text('Enter a permitted HTTPS sign-in URL.'), findsOneWidget);
    expect(tester.widget<FilledButton>(button).onPressed, isNull);
  });

  testWidgets('direct API login supports configurable endpoints without a pasted token', (tester) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final project = SecurityProject(name: 'Fixture', url: 'https://api.example.test');
    AuthProfile? captured;
    await tester.pumpWidget(MaterialApp(home: Builder(builder: (context) => Scaffold(
      body: TextButton(onPressed: () async {
        captured = await showDialog<AuthProfile>(context: context, builder: (_) =>
          QuickApiLoginDialog(project: project, target: project.startUrl, policy: ScanPolicy()));
      }, child: const Text('Open fixture')),
    ))));
    await tester.tap(find.text('Open fixture'));
    await tester.pumpAndSettle();
    final fields = find.byType(TextField);
    expect(tester.widget<TextField>(fields.at(0)).controller!.text, 'https://api.example.test/login');
    expect(tester.widget<TextField>(fields.at(2)).obscureText, isTrue);
    await tester.enterText(fields.at(0), 'https://api.example.test/auth/sign-in');
    await tester.enterText(fields.at(1), 'fixture-user');
    await tester.enterText(fields.at(2), 'fixture-password');
    await tester.tap(find.text('API login settings'));
    await tester.pumpAndSettle();
    final tokenPath = find.widgetWithText(TextField, 'JSON token path');
    await tester.ensureVisible(tokenPath);
    await tester.enterText(tokenPath, 'payload.access_token');
    await tester.ensureVisible(find.text('Sign in and scan'));
    await tester.tap(find.text('Sign in and scan'));
    await tester.pumpAndSettle();
    expect(captured?.loginUrl, 'https://api.example.test/auth/sign-in');
    expect(captured?.tokenPath, 'payload.access_token');
    expect(captured?.tokenDelivery, TokenDelivery.bearer);
    expect(captured?.mode, AuthMode.jsonLogin);
  });

  testWidgets('HTTP sign-in unlocks only after session consent', (tester) async {
    tester.view.physicalSize = const Size(800, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    SharedPreferences.setMockInitialValues({});
    final project = SecurityProject(name: 'Test', url: 'http://example.test:2020');
    await tester.pumpWidget(MaterialApp(home: ScanScreen(project: project)));
    await tester.pumpAndSettle();
    await tester.tap(find.text('After sign-in'));
    await tester.pumpAndSettle();
    final api = find.byKey(const ValueKey('method.false.false.false'));
    expect(tester.widget<DropdownButtonFormField<String>>(api).onChanged, isNull);
    final cleartext = find.text('Allow insecure HTTP sign-in for this scan');
    await tester.ensureVisible(cleartext);
    await tester.tap(cleartext);
    await tester.pumpAndSettle();
    expect(tester.widget<DropdownButtonFormField<String>>(api).onChanged, isNotNull);
    await tester.tap(api);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Direct API sign-in').last);
    await tester.pumpAndSettle();
    expect(find.text('Sign in to API and scan'), findsOneWidget);
    await tester.tap(cleartext);
    await tester.pumpAndSettle();
    expect(tester.widget<DropdownButtonFormField<String>>(api).onChanged, isNull);
  });

  testWidgets('project list shows branded empty state', (tester) async {
    await tester.pumpWidget(OdinSecurityApp(repository: ProjectRepository(MemoryStorage())));
    await tester.pumpAndSettle();
    expect(find.text('Odin Security'), findsOneWidget);
    expect(find.text('New project'), findsOneWidget);
  });
  testWidgets('stored Persian language and light theme are loaded', (tester) async {
    final memory = MemoryStorage();
    await UiPreferencesRepository(memory).save(const UiPreferences(language: 'fa', theme: 'light'));
    await tester.pumpWidget(OdinSecurityApp(repository: ProjectRepository(memory)));
    await tester.pumpAndSettle();
    final finder = find.text('پروژه جدید');
    expect(finder, findsOneWidget);
    expect(Directionality.of(tester.element(finder)), TextDirection.rtl);
    expect(Theme.of(tester.element(finder)).brightness, Brightness.light);
  });
}
