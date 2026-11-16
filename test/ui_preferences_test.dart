import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/ui_preferences.dart';
import 'project_storage_test.dart' show MemoryStorage;

void main() {
  test('UI preferences persist and invalid values fall back', () async {
    final memory = MemoryStorage();
    final repo = UiPreferencesRepository(memory);
    expect((await repo.load()).language, 'en');
    await repo.save(const UiPreferences(language: 'fa', theme: 'light'));
    expect((await repo.load()).language, 'fa');
    expect((await repo.load()).theme, 'light');
    await memory.write(UiPreferencesRepository.key, 'unknown:invalid');
    expect((await repo.load()).language, 'en');
    expect((await repo.load()).theme, 'dark');
  });
}
