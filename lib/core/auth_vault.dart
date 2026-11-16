import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'auth.dart';

abstract interface class CredentialStorage {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

class AndroidCredentialStorage implements CredentialStorage {
  final FlutterSecureStorage storage;
  AndroidCredentialStorage({FlutterSecureStorage? storage}) : storage = storage ?? const FlutterSecureStorage();
  @override
  Future<String?> read(String key) => storage.read(key: key);
  @override
  Future<void> write(String key, String value) => storage.write(key: key, value: value);
  @override
  Future<void> delete(String key) => storage.delete(key: key);
}

class AuthVault {
  final CredentialStorage storage;
  AuthVault({CredentialStorage? storage}) : storage = storage ?? AndroidCredentialStorage();
  String _legacyKey(String id) => 'odin_security.auth.v1.$id';
  String _key(String id) => 'odin_security.auth.v2.$id';

  Future<List<AuthProfile>> loadProfiles(String projectId) async {
    final value = await storage.read(_key(projectId));
    if (value != null) {
      return (jsonDecode(value) as List<dynamic>).map((item) => AuthProfile.fromJson(Map<String, dynamic>.from(item as Map))).toList();
    }
    final old = await storage.read(_legacyKey(projectId));
    if (old == null) return [];
    final profile = AuthProfile.fromJson(Map<String, dynamic>.from(jsonDecode(old) as Map));
    return profile.mode == AuthMode.none ? [] : [profile];
  }

  Future<void> saveProfiles(String projectId, List<AuthProfile> profiles) async {
    if (profiles.length > 20 || profiles.any((p) => p.mode == AuthMode.none) ||
        profiles.map((p) => p.name.trim().toLowerCase()).toSet().length != profiles.length) {
      throw StateError('Invalid or duplicate authentication profiles.');
    }
    await storage.write(_key(projectId), jsonEncode(profiles.map((p) => p.toJson()).toList()));
    await storage.delete(_legacyKey(projectId));
  }
}
