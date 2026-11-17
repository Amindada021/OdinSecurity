import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/auth.dart';
import 'package:odin_security/core/auth_vault.dart';

class MemoryCredentials implements CredentialStorage {
  final values = <String, String>{};
  @override
  Future<String?> read(String key) async => values[key];
  @override
  Future<void> write(String key, String value) async { values[key] = value; }
  @override
  Future<void> delete(String key) async { values.remove(key); }
}

void main() {
  final origin = Uri.parse('https://example.test/');
  AuthProfile profile(String name) => AuthProfile(name: name, mode: AuthMode.bearer, target: origin, secret: 'fixture');
  test('multiple identities round-trip in separate projects', () async {
    final storage = MemoryCredentials();
    final vault = AuthVault(storage: storage);
    await vault.saveProfiles('a', [profile('Manager'), profile('Accountant')]);
    expect((await vault.loadProfiles('a')).map((p) => p.name), ['Manager', 'Accountant']);
    expect(await vault.loadProfiles('b'), isEmpty);
    await expectLater(vault.saveProfiles('a', [profile('Manager'), profile('manager')]), throwsStateError);
  });
  test('legacy profile migrates without resurfacing after deletion', () async {
    final store = MemoryCredentials();
    store.values['odin_security.auth.v1.a'] = jsonEncode(profile('Old').toJson());
    final vault = AuthVault(storage: store);
    expect((await vault.loadProfiles('a')).single.name, 'Old');
    await vault.saveProfiles('a', []);
    expect(await vault.loadProfiles('a'), isEmpty);
    expect(await store.read('odin_security.auth.v1.a'), isNull);
  });
  test('validation uses the same origin and can check rejection without a marker', () {
    expect(() => AuthProfile(mode: AuthMode.bearer, target: origin, secret: 'fixture', validationUrl: 'https://other.test/path', validationMarker: 'ok'), throwsFormatException);
    expect(AuthProfile(mode: AuthMode.bearer, target: origin, secret: 'fixture', validationUrl: 'https://example.test/path').validationMarker, isEmpty);
    final a = AuthProfile(mode: AuthMode.bearer, target: origin, secret: 'fixture', validationUrl: 'https://example.test/path', validationMarker: 'user-test');
    expect(AuthProfile.fromJson(a.toJson()).validationMarker, 'user-test');
    expect(Authenticator.validationMatches(200, 'login', 'user-test'), isFalse);
    expect(Authenticator.validationMatches(302, 'user-test', 'user-test'), isFalse);
    expect(Authenticator.validationMatches(200, 'user-test', 'user-test'), isTrue);
  });
}
