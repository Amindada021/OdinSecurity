import 'package:flutter/material.dart';
import 'core/auth.dart';
import 'core/project.dart';

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
  late final TextEditingController username, secret, header, login, usernameField, passwordField, tokenPath;
  String? error;

  @override
  void initState() {
    super.initState();
    final a = widget.existing;
    mode = a?.mode ?? AuthMode.bearer;
    target = a != null && widget.project.targets.contains(a.target) ? a.target : widget.project.startUrl;
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
    for (final c in [username, secret, header, login, usernameField, passwordField, tokenPath]) { c.dispose(); }
    super.dispose();
  }

  void submit() {
    try {
      Navigator.pop(context, AuthProfile(mode: mode, target: target, username: username.text,
        secret: secret.text, headerName: header.text, loginUrl: login.text,
        usernameField: usernameField.text, passwordField: passwordField.text, tokenPath: tokenPath.text.trim()));
    } on FormatException catch (e) {
      setState(() => error = e.message);
    }
  }

  Widget field(TextEditingController controller, String label, {bool obscure = false}) => TextField(
    controller: controller, obscureText: obscure, autocorrect: false,
    enableSuggestions: false, decoration: InputDecoration(labelText: label));

  @override
  Widget build(BuildContext context) {
    final isLogin = mode == AuthMode.jsonLogin || mode == AuthMode.formLogin;
    return AlertDialog(
      title: const Text('Authentication'),
      content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
        DropdownButtonFormField<AuthMode>(
          initialValue: mode,
          decoration: const InputDecoration(labelText: 'Method'),
          items: AuthMode.values.map((m) => DropdownMenuItem(value: m, child: Text(m.name))).toList(),
          onChanged: (v) => setState(() { mode = v!; error = null; }),
        ),
        DropdownButtonFormField<Uri>(
          initialValue: target,
          isExpanded: true,
          decoration: const InputDecoration(labelText: 'Credential origin'),
          items: widget.project.targets.toSet().map((u) => DropdownMenuItem(value: u, child: Text(u.host, overflow: TextOverflow.ellipsis))).toList(),
          onChanged: (v) => setState(() => target = v!),
        ),
        if (isLogin || mode == AuthMode.basic) field(username, 'Username / email / mobile'),
        if (mode != AuthMode.none) field(secret, isLogin || mode == AuthMode.basic ? 'Password' : 'Token / cookie / key', obscure: true),
        if (mode == AuthMode.apiKey) field(header, 'API key header'),
        if (isLogin) ...[
          field(login, 'Exact HTTPS login endpoint'),
          field(usernameField, 'Username field'),
          field(passwordField, 'Password field'),
          field(tokenPath, 'JSON token path (blank = session cookie)'),
        ],
        const Padding(padding: EdgeInsets.only(top: 12), child: Text('Credentials are saved separately in encrypted storage. Only the selected HTTPS origin receives them.')),
        if (error != null) Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
      ])),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: submit, child: const Text('Save')),
      ],
    );
  }
}
