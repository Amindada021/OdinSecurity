import 'package:flutter/material.dart';
import 'core/auth.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
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

  @override
  void initState() {
    super.initState();
    endpoint = TextEditingController(text: widget.target.resolve('/login').toString());
    tokenPath = TextEditingController(text: 'token');
  }

  @override
  void dispose() {
    for (final field in [endpoint, tokenPath, username, password, usernameField, passwordField, header]) {
      field.dispose();
    }
    super.dispose();
  }

  void submit() {
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
      password.clear();
      Navigator.pop(context, profile);
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
        initialValue: delivery, isExpanded: true,
        decoration: const InputDecoration(label: LText('Send authentication as')),
        items: TokenDelivery.values.map((value) => DropdownMenuItem(value: value, child: LText(tokenDeliveryLabel(value)))).toList(),
        onChanged: (value) => setState(() { if (value != null) delivery = value; error = null; }),
      ),
      if (delivery == TokenDelivery.apiKey || delivery == TokenDelivery.customHeader)
        field(header, 'Credential header name'),
          DropdownButtonFormField<AuthMode>(initialValue: mode, isExpanded: true,
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
      TextButton(onPressed: () => Navigator.pop(context), child: const LText('Cancel')),
      FilledButton(onPressed: submit, child: const LText('Sign in and scan')),
    ],
  );
}
