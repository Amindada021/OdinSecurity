import 'dart:convert';
import 'auth.dart';
import 'project_storage.dart';

class ApiLoginPreferences {
  final String loginUrl, usernameField, passwordField, tokenPath, headerName;
  final TokenDelivery delivery;
  final AuthMode mode;
  const ApiLoginPreferences({
    this.loginUrl = '', this.usernameField = 'username',
    this.passwordField = 'password', this.tokenPath = 'token',
    this.headerName = 'X-API-Key', this.delivery = TokenDelivery.bearer,
    this.mode = AuthMode.jsonLogin,
  });

  Map<String, dynamic> toJson() => {
    'loginUrl': loginUrl,
    'usernameField': usernameField, 'passwordField': passwordField,
    'tokenPath': tokenPath, 'headerName': headerName,
    'delivery': delivery.name, 'mode': mode.name,
  };

  factory ApiLoginPreferences.fromJson(Map<String, dynamic> json) {
    String safeField(String key, String fallback) {
      final raw = json[key];
      return raw is String && raw.length <= 120 &&
              !raw.contains(RegExp(r'[\\r\\n]')) ? raw : fallback;
    }
    final url = json['loginUrl'];
    final parsed = url is String && url.length <= 2048 ? Uri.tryParse(url) : null;
    final safeUrl = parsed != null && parsed.userInfo.isEmpty &&
        parsed.query.isEmpty && parsed.fragment.isEmpty ? url as String : '';
    final d = json['delivery'];
    final m = json['mode'];
    return ApiLoginPreferences(
      loginUrl: safeUrl,
      usernameField: safeField('usernameField', 'username'),
      passwordField: safeField('passwordField', 'password'),
      tokenPath: safeField('tokenPath', 'token'),
      headerName: safeField('headerName', 'X-API-Key'),
      delivery: d is String
          ? TokenDelivery.values.where((v) => v.name == d).firstOrNull ?? TokenDelivery.bearer
          : TokenDelivery.bearer,
      mode: m == 'formLogin' ? AuthMode.formLogin : AuthMode.jsonLogin,
    );
  }
}

class ApiLoginPreferencesRepository {
  final ProjectStorage storage;
  ApiLoginPreferencesRepository(this.storage);
  String key(String projectId, Uri target) =>
    'odin_security.api_login.v1.$projectId.${base64Url.encode(utf8.encode(target.origin))}';

  Future<ApiLoginPreferences> load(String projectId, Uri target) async {
    final raw = await storage.read(key(projectId, target));
    if (raw == null) return const ApiLoginPreferences();
    try { return ApiLoginPreferences.fromJson(Map<String, dynamic>.from(jsonDecode(raw) as Map)); }
    catch (_) { return const ApiLoginPreferences(); }
  }

  Future<void> save(String projectId, Uri target, ApiLoginPreferences data) =>
      storage.write(key(projectId, target), jsonEncode(data.toJson()));
}
