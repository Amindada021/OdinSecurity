import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/material.dart';
import 'package:odin_security/core/ui_preferences.dart';
import 'package:odin_security/main.dart';
import 'package:odin_security/core/project_storage.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
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
