import 'dart:convert';

import 'auth.dart';
import 'project_storage.dart';

/// Persistent project UI preferences only. Never store credentials or cookies.
class QuickScanPreferences {
  final String target, method, loginUrl, headerName, identityName;
  final TokenDelivery delivery;
  const QuickScanPreferences({
    this.target = '', this.method = 'public', this.loginUrl = '/login',
    this.headerName = 'X-API-Key', this.identityName = '',
    this.delivery = TokenDelivery.bearer,
  });

  static const methods = {'public', 'browser', 'api', 'token', 'saved'};

  QuickScanPreferences copyWith({
    String? target, String? method, String? loginUrl, String? headerName,
    String? identityName, TokenDelivery? delivery,
  }) => QuickScanPreferences(
    target: target ?? this.target, method: method ?? this.method,
    loginUrl: loginUrl ?? this.loginUrl, headerName: headerName ?? this.headerName,
    identityName: identityName ?? this.identityName,
    delivery: delivery ?? this.delivery,
  );

  Map<String, dynamic> toJson() => {
    'target': target, 'method': method, 'loginUrl': loginUrl,
    'headerName': headerName, 'identityName': identityName,
    'delivery': delivery.name,
  };

  factory QuickScanPreferences.fromJson(Map<String, dynamic> json) {
    final rawMethod = json['method'];
    final rawTarget = json['target'];
    final rawUrl = json['loginUrl'];
    final rawHeader = json['headerName'];
    final rawName = json['identityName'];
    final rawDelivery = json['delivery'];
    final safeTarget = rawTarget is String && rawTarget.length <= 2048 &&
            Uri.tryParse(rawTarget)?.userInfo.isEmpty == true &&
            Uri.tryParse(rawTarget)?.query.isEmpty == true
        ? rawTarget : '';
    final safeUrl = rawUrl is String && rawUrl.length <= 2048 &&
            Uri.tryParse(rawUrl)?.userInfo.isEmpty == true &&
            Uri.tryParse(rawUrl)?.query.isEmpty == true &&
            Uri.tryParse(rawUrl)?.fragment.isEmpty == true
        ? rawUrl : '/login';
    return QuickScanPreferences(
      target: safeTarget,
      method: rawMethod is String && methods.contains(rawMethod) ? rawMethod : 'public',
      loginUrl: safeUrl,
      headerName: rawHeader is String && RegExp(r'^[A-Za-z0-9-]{1,80}$').hasMatch(rawHeader)
          ? rawHeader : 'X-API-Key',
      identityName: rawName is String && rawName.length <= 80 ? rawName : '',
      delivery: rawDelivery is String
          ? TokenDelivery.values.where((d) => d.name == rawDelivery).firstOrNull ?? TokenDelivery.bearer
          : TokenDelivery.bearer,
    );
  }
}

class QuickScanPreferencesRepository {
  final ProjectStorage storage;
  QuickScanPreferencesRepository(this.storage);
  String key(String id) => 'odin_security.quick_ui.v1.$id';

  Future<QuickScanPreferences> load(String projectId) async {
    final raw = await storage.read(key(projectId));
    if (raw == null) return const QuickScanPreferences();
    try {
      return QuickScanPreferences.fromJson(Map<String, dynamic>.from(jsonDecode(raw) as Map));
    } catch (_) {
      return const QuickScanPreferences();
    }
  }

  Future<void> save(String projectId, QuickScanPreferences settings) =>
      storage.write(key(projectId), jsonEncode(settings.toJson()));
}

/// The draggable network divider size is independent of quick scan settings.
class LoginPanelPreferencesRepository {
  final ProjectStorage storage;
  LoginPanelPreferencesRepository(this.storage);
  String key(String id) => 'odin_security.login_panel_fraction.v1.$id';

  static double normalize(double value) => value.isFinite
      ? value.clamp(0.20, 0.74).toDouble() : 0.45;

  Future<double> load(String projectId) async {
    final raw = await storage.read(key(projectId));
    final fraction = double.tryParse(raw ?? '') ?? 0.45;
    return normalize(fraction);
  }

  Future<void> save(String projectId, double fraction) =>
      storage.write(key(projectId), normalize(fraction).toString());
}
