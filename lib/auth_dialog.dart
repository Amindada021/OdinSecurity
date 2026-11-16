import 'package:flutter/material.dart';
import 'localized.dart';
import 'core/auth.dart';
import 'core/project.dart';
import 'browser_login_screen.dart';

class AuthDialog extends StatefulWidget {
  final SecurityProject project;
  final AuthProfile? existing;
  const AuthDialog({super.key, required this.project, this.existing});
  @override
  State<AuthDialog> createState() => _AuthDialogState();
}

class _AuthDialogState extends State<AuthDialog> {
  late AuthMode mode;
  late Uri target;
  late final TextEditingController name, username, secret, header, login, usernameField, passwordField, tokenPath, validationUrl, validationMarker;
  String? error;
  String cookiePath = '/';
  bool importing = false;

  @override
  void initState() {
    super.initState();
    final a = widget.existing;
    mode = a?.mode ?? AuthMode.bearer;
    cookiePath = a?.cookiePath ?? '/';
    target = a != null && widget.project.targets.contains(a.target) ? a.target : widget.project.startUrl;
    name = TextEditingController(text: a?.name ?? '');
    validationUrl = TextEditingController(text: a?.validationUrl);
    validationMarker = TextEditingController(text: a?.validationMarker);
    username = TextEditingController(text: a?.username);
    secret = TextEditingController(text: a?.secret);
    header = TextEditingController(text: a?.headerName ?? 'X-API-Key');
    login = TextEditingController(text: a?.loginUrl);
    usernameField = TextEditingController(text: a?.usernameField ?? 'username');
    passwordField = TextEditingController(text: a?.passwordField ?? 'password');
    tokenPath = TextEditingController(text: a?.tokenPath);
  }

  @override
  void dispose() {
    for (final c in [name, username, secret, header, login, usernameField, passwordField, tokenPath, validationUrl, validationMarker]) { c.dispose(); }
    super.dispose();
  }

  Future<void> browserLogin() async {
    if (importing) return;
    try {
      final loginUri = SecurityProject.parseTarget(login.text.trim());
      if (target.scheme != 'https' || !SecurityProject.sameOrigin(target, loginUri)) {
        throw const FormatException('Browser sign-in must use the selected HTTPS origin.');
      }
      setState(() { importing = true; error = null; });
      final captured = await Navigator.of(context).push<String>(MaterialPageRoute(builder: (_) => BrowserLoginScreen(target: target, login: loginUri)));
      if (captured != null && mounted) {
        setState(() { secret.text = captured; cookiePath = target.path.isEmpty ? '/' : target.path; });
      }
    } on FormatException catch (e) {
      if (mounted) setState(() => error = e.message);
    } finally {
      if (mounted) setState(() => importing = false);
    }
  }

  void submit() {
    try {
      Navigator.pop(context, AuthProfile(mode: mode, target: target, name: name.text.trim(), cookiePath: cookiePath, validationUrl: validationUrl.text.trim(), validationMarker: validationMarker.text, username: username.text,
        secret: secret.text, headerName: header.text, loginUrl: login.text,
        usernameField: usernameField.text, passwordField: passwordField.text, tokenPath: tokenPath.text.trim()));
    } on FormatException catch (e) {
      setState(() => error = e.message);
    }
  }

  Widget field(TextEditingController controller, String label, {bool obscure = false}) => TextField(
    controller: controller, obscureText: obscure, autocorrect: false,
    enableSuggestions: false, decoration: InputDecoration(label: LText(label)));

  @override
  Widget build(BuildContext context) {
    final isLogin = mode == AuthMode.jsonLogin || mode == AuthMode.formLogin;
    return AlertDialog(
      title: const LText('Authentication'),
      content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
        field(name, 'Profile name (e.g. accountant)'),
        DropdownButtonFormField<AuthMode>(
          initialValue: mode,
          decoration: const InputDecoration(label: LText('Method')),
          items: AuthMode.values.where((m) => m != AuthMode.none).map((m) => DropdownMenuItem(value: m, child: Text(m.name))).toList(),
          onChanged: (v) => setState(() { if (mode != v) { secret.clear(); cookiePath = '/'; } mode = v!; error = null; }),
        ),
        DropdownButtonFormField<Uri>(
          initialValue: target,
          isExpanded: true,
          decoration: const InputDecoration(label: LText('Credential origin')),
          items: widget.project.targets.toSet().map((u) => DropdownMenuItem(value: u, child: Text(u.host, overflow: TextOverflow.ellipsis))).toList(),
          onChanged: (v) => setState(() { if (target != v) { secret.clear(); cookiePath = '/'; } target = v!; }),
        ),
        if (isLogin || mode == AuthMode.basic) field(username, 'Username / email / mobile'),
        if (mode != AuthMode.none) field(secret, isLogin || mode == AuthMode.basic ? 'Password' : 'Token / cookie / key', obscure: true),
        if (mode == AuthMode.apiKey) field(header, 'API key header'),
        if (mode == AuthMode.cookie) ...[
          field(login, 'Browser sign-in URL (optional)'),
          OutlinedButton(onPressed: importing ? null : browserLogin, child: const LText('Sign in using browser and OTP')),
          Text('Cookie path scope: $cookiePath'),
        ],
        if (isLogin) ...[
          field(login, 'Exact HTTPS login endpoint'),
          field(usernameField, 'Username field'),
          field(passwordField, 'Password field'),
          field(tokenPath, 'JSON token path (blank = session cookie)'),
        ],
        field(validationUrl, 'Protected HTTPS URL (optional)'),
        field(validationMarker, 'Expected response marker (optional)', obscure: true),
        const LText('If a protected URL is configured, the marker must appear in its 2xx response before scanning.'),
        const Padding(padding: EdgeInsets.only(top: 12), child: LText('Credentials are saved separately in encrypted storage. Only the selected HTTPS origin receives them.')),
        if (error != null) LText(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
      ])),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const LText('Cancel')),
        FilledButton(onPressed: submit, child: const LText('Save')),
      ],
    );
  }
}
