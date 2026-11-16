import 'package:flutter/material.dart';
import 'localized.dart';
import 'package:flutter/services.dart';
import 'core/auth.dart';
import 'core/oauth_grant.dart';
import 'core/oauth_flow.dart';
import 'core/project.dart';

class OAuthDialog extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  const OAuthDialog({super.key, required this.project, required this.target});
  @override
  State<OAuthDialog> createState() => _OAuthDialogState();
}

class _OAuthDialogState extends State<OAuthDialog> {
  final name = TextEditingController(), client = TextEditingController(),
    authorization = TextEditingController(), token = TextEditingController(),
    scopes = TextEditingController(text: 'openid profile'),
    verification = TextEditingController(), marker = TextEditingController();
  bool permitted = false, busy = false;
  String? error;

  @override
  void dispose() {
    for (final c in [name, client, authorization, token, scopes, verification, marker]) { c.dispose(); }
    super.dispose();
  }

  Future<void> signIn() async {
    if (!permitted || busy) return;
    setState(() { busy = true; error = null; });
    try {
      if (!widget.project.contains(widget.target) || widget.target.scheme != 'https') throw const FormatException('Select an approved HTTPS API origin.');
      final grant = OAuthGrant(clientId: client.text.trim(),
        authorizationEndpoint: authorization.text.trim(), tokenEndpoint: token.text.trim(),
        scopes: scopes.text.trim().split(RegExp(r'\s+')));
      // This local draft is never persisted or used as an HTTP credential.
      final draft = AuthProfile(name: name.text.trim(), mode: AuthMode.bearer,
        target: widget.target, secret: 'pending-oauth-exchange', oauth: grant,
        validationUrl: verification.text.trim(), validationMarker: marker.text);
      final profile = await OAuthFlow().signIn(draft);
      if (mounted) Navigator.pop(context, profile);
    } on FormatException catch (e) {
      if (mounted) setState(() => error = e.message);
    } catch (_) {
      if (mounted) setState(() => error = 'OAuth sign-in was cancelled or failed. Check public-client registration, endpoints and scopes.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Widget field(TextEditingController controller, String label, {bool obscure = false}) => TextField(
    controller: controller, enabled: !busy, obscureText: obscure,
    autocorrect: false, enableSuggestions: false, decoration: InputDecoration(label: LText(label)),
    onChanged: (_) => setState(() { permitted = false; error = null; }));

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('OAuth 2.0 / OIDC'),
    content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
      Text('API origin: ${widget.target.origin}'),
      const LText('Register a public native client with Authorization Code + PKCE and the exact redirect URI below. Do not use a client secret. Request only authorized, preferably read-only scopes.'),
      SelectableText(OAuthGrant.redirectUri),
      TextButton.icon(onPressed: () => Clipboard.setData(const ClipboardData(text: OAuthGrant.redirectUri)), icon: const Icon(Icons.copy), label: const LText('Copy redirect URI')),
      field(name, 'Identity name'),
      field(client, 'Registered client ID'),
      field(authorization, 'HTTPS authorization endpoint'),
      field(token, 'HTTPS token endpoint'),
      field(scopes, 'Scopes (space separated)'),
      field(verification, 'Protected validation URL'),
      field(marker, 'Expected response marker', obscure: true),
      CheckboxListTile(value: permitted, title: const LText('I authorize these provider endpoints and this registered application.'), onChanged: busy ? null : (v) => setState(() => permitted = v ?? false)),
      if (busy) const LinearProgressIndicator(),
      if (error != null) LText(error!),
    ])),
    actions: [
      TextButton(onPressed: busy ? null : () => Navigator.pop(context), child: const LText('Cancel')),
      FilledButton(onPressed: permitted && !busy ? signIn : null, child: const LText('Sign in with browser')),
    ],
  );
}
