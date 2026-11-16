import 'package:flutter/material.dart';
import 'localized.dart';
import 'core/project.dart';
import 'core/auth.dart';
import 'manual_request_screen.dart';
import 'core/scan_policy.dart';
import 'core/traffic_journal.dart';

class TrafficLoggerScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  final AuthProfile? auth;
  const TrafficLoggerScreen({super.key, required this.project, required this.policy, this.auth});
  @override
  State<TrafficLoggerScreen> createState() => _TrafficLoggerScreenState();
}

class _TrafficLoggerScreenState extends State<TrafficLoggerScreen> {
  String filter = 'all', search = '';
  final journal = TrafficJournal.shared;

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Traffic logger'), actions: [
      IconButton(tooltip: tr(context, 'Clear'), icon: const Icon(Icons.delete_outline),
        onPressed: () => journal.clear(widget.project.id)),
    ]),
    body: StreamBuilder<void>(stream: journal.changes, builder: (context, _) {
      final entries = journal.forProject(widget.project, widget.policy);
      final shown = entries.where((entry) =>
        (filter == 'all' || filter == entry.source ||
          (filter == 'errors' && (entry.status == null || entry.status! >= 400))) &&
        entry.route.toString().toLowerCase().contains(search.trim().toLowerCase())).toList();
      return ListView.builder(padding: const EdgeInsets.all(12), itemCount: shown.length + 1,
        itemBuilder: (context, index) {
          if (index == 0) return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const LText('Session-only traffic metadata from Odin Security requests. Other apps, browser traffic, authentication exchanges, bodies, headers and query values are not captured. Paths may be sensitive.'),
            Text('${uiNumber(context, shown.length)} / ${uiNumber(context, entries.length)}'),
            TextField(onChanged: (v) => setState(() => search = v), decoration: const InputDecoration(label: LText('Search routes'))),
            DropdownButtonFormField<String>(initialValue: filter, items: [
              for (final value in ['all', 'manual', 'passive', 'cors', 'errors'])
                DropdownMenuItem(value: value, child: LText(value == 'all' ? 'All requests' : value)),
            ], onChanged: (v) => setState(() => filter = v ?? 'all')),
          ]);
          final entry = shown[index - 1];
          final details = [
            entry.status == null ? 'No response' : 'HTTP ${entry.status}',
            '${entry.elapsedMs} ms', entry.source,
            if (entry.capturedBytes != null) '${entry.capturedBytes} bytes${entry.truncated ? "+" : ""}',
            if (entry.hadQuery) 'query omitted',
          ].join(' | ');
          return ListTile(title: Text('${entry.method} ${entry.route}'), subtitle: Text(details),
            trailing: TrafficJournal.canInspect(entry, widget.project, widget.policy) ? IconButton(
              tooltip: tr(context, 'Open request inspector'), icon: const Icon(Icons.http),
              onPressed: () {
                final auth = widget.auth;
                Navigator.of(context).push(MaterialPageRoute(builder: (_) => ManualRequestScreen(
                  project: widget.project, target: entry.route, policy: widget.policy,
                  initialMethod: entry.method,
                  auth: auth != null && SecurityProject.sameOrigin(auth.target, entry.route) ? auth : null,
                )));
              },
            ) : null,
          );
        });
    }),
  );
}
