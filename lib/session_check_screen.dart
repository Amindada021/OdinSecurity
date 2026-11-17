import 'package:flutter/material.dart';
import 'core/auth.dart';
import 'core/project.dart';
import 'core/scan_policy.dart';
import 'localized.dart';

/// Tests only the selected identity/its configured verification endpoint.
/// Neither the session nor the returned credential is kept in UI state.
class SessionCheckScreen extends StatefulWidget {
  final SecurityProject project;
  final Uri target;
  final AuthProfile profile;
  final ScanPolicy policy;
  const SessionCheckScreen({super.key, required this.project, required this.target, required this.profile, required this.policy});

  @override
  State<SessionCheckScreen> createState() => _SessionCheckScreenState();
}

class _SessionCheckScreenState extends State<SessionCheckScreen> {
  bool approved = false, busy = false;
  String? outcome;

  Future<void> run() async {
    if (!approved || busy) return;
    setState(() { approved = false; busy = true; outcome = null; });
    try {
      if (!widget.project.contains(widget.target) || !widget.policy.permits(widget.target) ||
          !SecurityProject.sameOrigin(widget.profile.target, widget.target)) throw StateError('Target outside scope.');
      final session = await Authenticator().authenticate(widget.project, widget.profile,
        authorized: true, permits: widget.policy.permits);
      final applicable = session.headersFor(widget.target).isNotEmpty;
      final status = !applicable ? 'Identity does not have applicable credentials for the selected target.' :
        widget.profile.validationUrl.isEmpty ? 'Credentials prepared; no protected verification was configured.' :
        session.verification;
      if (mounted) setState(() => outcome = status);
    } catch (_) {
      if (mounted) setState(() => outcome = 'Session verification failed. Check scope, expiry and identity configuration.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Session check')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      Text(widget.profile.name, style: Theme.of(context).textTheme.titleLarge),
      Text(widget.profile.mode.name),
      SelectableText(widget.target.toString()),
      const LText('Check the saved identity against its configured HTTPS login and protected verification endpoint. No credential values or response bodies are displayed.'),
      if (widget.profile.validationUrl.isEmpty) const LText('No protected verification endpoint configured. Session validity cannot be confirmed.'),
      if (widget.profile.validationUrl.isNotEmpty) ...[
        const LText('Protected verification URL'),
        SelectableText(widget.profile.validationUrl, textDirection: TextDirection.ltr),
      ],
      if (widget.profile.isLogin) ...[
        const LText('Login URL'),
        SelectableText(widget.profile.loginUrl, textDirection: TextDirection.ltr),
      ],
      if (widget.profile.oauth?.expiresAt != null)
        Text(tr(context, 'Token expiration') + ': ' + widget.profile.oauth!.expiresAt!.toLocal().toString()),
      CheckboxListTile(value: approved, title: const LText('I authorize checking this saved identity.'),
        onChanged: busy ? null : (v) => setState(() => approved = v ?? false)),
      FilledButton(onPressed: busy || !approved ? null : run, child: const LText('Check session')),
      if (busy) const LinearProgressIndicator(),
      if (outcome != null) LText(outcome!),
    ]),
  );
}
