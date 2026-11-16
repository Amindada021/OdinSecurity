import 'project_storage.dart';

class UiPreferences {
  final String language, theme;
  const UiPreferences({this.language = 'en', this.theme = 'dark'});
  UiPreferences copyWith({String? language, String? theme}) =>
    UiPreferences(language: language ?? this.language, theme: theme ?? this.theme);
}

class UiPreferencesRepository {
  final ProjectStorage storage;
  UiPreferencesRepository(this.storage);
  static const key = 'odin_security.ui.v1';

  Future<UiPreferences> load() async {
    final parts = (await storage.read(key) ?? '').split(':');
    if (parts.length != 2) return const UiPreferences();
    return UiPreferences(language: ['en', 'fa'].contains(parts[0]) ? parts[0] : 'en',
      theme: ['dark', 'light', 'system'].contains(parts[1]) ? parts[1] : 'dark');
  }

  Future<void> save(UiPreferences value) {
    if (!['en', 'fa'].contains(value.language) || !['dark', 'light', 'system'].contains(value.theme)) {
      throw const FormatException('Invalid UI preferences.');
    }
    return storage.write(key, '${value.language}:${value.theme}');
  }
}
