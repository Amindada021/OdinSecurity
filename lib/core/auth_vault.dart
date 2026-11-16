import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'auth.dart';

class AuthVault {
  final FlutterSecureStorage storage;
  AuthVault({FlutterSecureStorage? storage}) : storage = storage ?? const FlutterSecureStorage();
  String _key(String projectId) => 'odin_security.auth.v1.$projectId';

  Future<void> save(String projectId, AuthProfile profile) =>
      storage.write(key: _key(projectId), value: jsonEncode(profile.toJson()));

  Future<AuthProfile?> load(String projectId) async {
    final value = await storage.read(key: _key(projectId));
    return value == null ? null : AuthProfile.fromJson(Map<String, dynamic>.from(jsonDecode(value) as Map));
  }

  Future<void> clear(String projectId) => storage.delete(key: _key(projectId));
}
