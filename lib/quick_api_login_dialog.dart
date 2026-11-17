import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/auth.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'core/project_storage.dart';
import 'core/api_login_preferences.dart';
import 'localized.dart';

String tokenDeliveryLabel(TokenDelivery delivery) => switch (delivery) {
  TokenDelivery.bearer => 'Bearer (Authorization)',
  TokenDelivery.raw => 'Raw token (Authorization)',
  TokenDelivery.apiKey => 'API key header',
  TokenDelivery.customHeader => 'Custom header',
  TokenDelivery.cookie => 'Cookie session',
};

class QuickApiLoginDialog extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final ScanPolicy policy;
  final bool allowInsecureHttp;
  const QuickApiLoginDialog({super.key, required this.project, required this.target, required this.policy, this.allowInsecureHttp = false});

  @override
  State<QuickApiLoginDialog> createState() => _QuickApiLoginDialogState();
}

class _QuickApiLoginDialogState extends State<QuickApiLoginDialog> {
  late final TextEditingController endpoint, tokenPath;
  final username = TextEditingController(), password = TextEditingController();
  final usernameField = TextEditingController(text: 'username');
  final passwordField = TextEditingController(text: 'password');
  final header = TextEditingController(text: 'X-API-Key');
  TokenDelivery delivery = TokenDelivery.bearer;
  AuthMode mode = AuthMode.jsonLogin;
  String? error;
  bool loadingSettings = true;
  Future<ApiLoginPreferencesRepository> _repository() async =>
      ApiLoginPreferencesRepository(PreferencesStorage(await SharedPreferences.getInstance()));

  Future<void> loadSettings() async {
    try {
      final value = await (await _repository()).load(widget.project.id, widget.target);
      if (!mounted) return;
      setState(() {
        if (value.loginUrl.isNotEmpty) endpoint.text = value.loginUrl;
        usernameField.text = value.usernameField;
        passwordField.text = value.passwordField;
        tokenPath.text = value.tokenPath;
        header.text = value.headerName;
        delivery = value.delivery;
        mode = value.mode;
      });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not restore API login settings.');
    } finally {
      if (mounted) setState(() => loadingSettings = false);
    }
  }

  Future<void> saveSettings() async {
    final raw = endpoint.text.trim();
    final uri = Uri.tryParse(raw);
    final safeLoginUrl = uri == null || uri.userInfo.isNotEmpty
        ? widget.target.resolve('/login').toString()
        : (raw.startsWith('/')
            ? (uri.path.isEmpty ? '/login' : uri.path)
            : uri.replace(query: '', fragment: '').toString());
    final value = ApiLoginPreferences(
      loginUrl: safeLoginUrl,
      usernameField: usernameField.text.trim(),
      passwordField: passwordField.text.trim(),
      tokenPath: tokenPath.text.trim(),
      headerName: header.text.trim(),
      delivery: delivery,
      mode: mode,
    );
    await (await _repository()).save(widget.project.id, widget.target, value);
  }

  @override
  void initState() {
    super.initState();
    endpoint = TextEditingController(text: widget.target.resolve('/login').toString());
    tokenPath = TextEditingController(text: 'token');
    loadSettings();
  }

  @override
  void dispose() {
    for (final field in [endpoint, tokenPath, username, password, usernameField, passwordField, header]) {
      field.dispose();
    }
    super.dispose();
  }

  Future<void> submit() async {
    if (loadingSettings) return;
    try {
      if (username.text.trim().isEmpty || password.text.isEmpty ||
          (delivery != TokenDelivery.cookie && tokenPath.text.trim().isEmpty)) {
        throw const FormatException('Complete the API sign-in fields.');
      }
      final raw = endpoint.text.trim();
      final login = SecurityProject.parseTarget(raw.startsWith('/') && !raw.startsWith('//')
        ? widget.target.resolve(raw).toString() : raw);
      final profile = AuthProfile(mode: mode, target: widget.target, name: 'Automatic API sign-in',
        loginUrl: login.toString(), username: username.text.trim(), secret: password.text,
        usernameField: usernameField.text.trim(), passwordField: passwordField.text.trim(),
        tokenPath: delivery == TokenDelivery.cookie ? '' : tokenPath.text.trim(),
        tokenDelivery: delivery, headerName: header.text.trim(), allowInsecureHttp: widget.allowInsecureHttp);
      Authenticator.validateScope(widget.project, profile, authorized: true, permits: widget.policy.permits);
      await saveSettings();
      password.clear();
      if (mounted) Navigator.pop(context, profile);
    } catch (_) {
      setState(() => error = 'Complete the API sign-in fields using a permitted endpoint on the selected target.');
    }
  }

  Widget field(TextEditingController controller, String label, {bool obscure = false}) => Padding(
    padding: const EdgeInsets.only(bottom: 10),
    child: TextField(controller: controller, autocorrect: false, enableSuggestions: false,
      obscureText: obscure, textDirection: TextDirection.ltr,
      decoration: InputDecoration(label: LText(label))),
  );

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const LText('Direct API sign-in'),
    content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(widget.target.host, style: Theme.of(context).textTheme.titleMedium),
      const LText('API endpoint and field mapping are remembered for this target. Username and password are not saved.'),
      if (loadingSettings) const LinearProgressIndicator(),
      const LText('Credentials are used once for this scan and are not saved. The sign-in request and token stay on the selected origin.'),
      const SizedBox(height: 12),
      field(endpoint, 'Exact login endpoint'),
      field(username, 'Username / email / mobile'),
      field(password, 'Password', obscure: true),
      ExpansionTile(
        title: const LText('API login settings'),
        childrenPadding: const EdgeInsets.symmetric(horizontal: 4),
        children: [
      DropdownButtonFormField<TokenDelivery>(
        key: ValueKey('api.delivery.${delivery.name}'),
        initialValue: delivery, isExpanded: true,
        decoration: const InputDecoration(label: LText('Send authentication as')),
        items: TokenDelivery.values.map((value) => DropdownMenuItem(value: value, child: LText(tokenDeliveryLabel(value)))).toList(),
        onChanged: (value) => setState(() { if (value != null) delivery = value; error = null; }),
      ),
      if (delivery == TokenDelivery.apiKey || delivery == TokenDelivery.customHeader)
        field(header, 'Credential header name'),
          DropdownButtonFormField<AuthMode>(key: ValueKey('api.mode.${mode.name}'),
            initialValue: mode, isExpanded: true,
            decoration: const InputDecoration(label: LText('Login request format')),
            items: const [
              DropdownMenuItem(value: AuthMode.jsonLogin, child: LText('JSON')),
              DropdownMenuItem(value: AuthMode.formLogin, child: LText('Form URL encoded')),
            ],
            onChanged: (value) => setState(() { if (value != null) mode = value; }),
          ),
          const SizedBox(height: 10),
          field(usernameField, 'Username field'),
          field(passwordField, 'Password field'),
          if (delivery != TokenDelivery.cookie) field(tokenPath, 'JSON token path'),
        ],
      ),
      if (error != null) LText(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
    ])),
    actions: [
      TextButton(onPressed: loadingSettings ? null : () async {
        try { await saveSettings(); } catch (_) { /* Never save secrets. */ }
        if (context.mounted) Navigator.pop(context);
      }, child: const LText('Cancel')),
      FilledButton(onPressed: loadingSettings ? null : submit, child: const LText('Sign in and scan')),
    ],
  );
}
