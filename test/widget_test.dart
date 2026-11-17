import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/material.dart';
import 'package:odin_security/core/ui_preferences.dart';
import 'package:odin_security/main.dart';
import 'package:odin_security/core/project_storage.dart';
import 'package:odin_security/core/project.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
  testWidgets('automatic scan is default and advanced tools are opt-in', (tester) async {
    SharedPreferences.setMockInitialValues({});
    final project = SecurityProject(name: 'Example', url: 'https://example.test');
    await tester.pumpWidget(MaterialApp(home: ScanScreen(project: project)));
    await tester.pumpAndSettle();
    expect(find.text('Automatic scan'), findsOneWidget);
    expect(find.text('Start automatic scan'), findsOneWidget);
    final start = tester.widget<FilledButton>(find.ancestor(of: find.text('Start automatic scan'), matching: find.byWidgetPredicate((widget) => widget is FilledButton)));
    expect(start.onPressed, isNull);
    expect(find.text('Representation test matrix'), findsNothing);
    await tester.tap(find.text('Advanced mode'));
    await tester.pumpAndSettle();
    expect(find.text('Representation test matrix'), findsOneWidget);
    expect(find.text('Start automatic scan'), findsNothing);
    await tester.tap(find.text('Automatic scan'));
    await tester.pumpAndSettle();
    expect(find.text('Start automatic scan'), findsOneWidget);
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
