import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'project.dart';

abstract interface class ProjectStorage {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
}

class PreferencesStorage implements ProjectStorage {
  final SharedPreferences preferences;
  PreferencesStorage(this.preferences);
  @override
  Future<String?> read(String key) async => preferences.getString(key);
  @override
  Future<void> write(String key, String value) async {
    if (!await preferences.setString(key, value)) throw StateError('Could not save local data.');
  }
}

/// Only project metadata is stored here. Credentials must use the secure vault.
class ProjectRepository {
  static const _key = 'odin_security.projects.v1';
  final ProjectStorage storage;
  ProjectRepository(this.storage);

  Future<List<SecurityProject>> load() async {
    final raw = await storage.read(_key);
    if (raw == null) return [];
    final list = jsonDecode(raw) as List<dynamic>;
    return list.map((item) => SecurityProject.fromJson(Map<String, dynamic>.from(item as Map))).toList();
  }

  Future<void> save(List<SecurityProject> projects) async {
    if (projects.map((p) => p.id).toSet().length != projects.length) {
      throw StateError('Duplicate project ID.');
    }
    await storage.write(_key, jsonEncode(projects.map((p) => p.toJson()).toList()));
  }
}
