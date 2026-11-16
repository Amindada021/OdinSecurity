import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'localized.dart';
import 'core/auth.dart';
import 'core/project.dart';
import 'core/project_storage.dart';
import 'core/route_inventory.dart';
import 'core/route_repository.dart';
import 'core/scan_policy.dart';
import 'manual_request_screen.dart';

Future<RouteRepository> routeRepository() async =>
  RouteRepository(PreferencesStorage(await SharedPreferences.getInstance()));

Future<bool> saveObservedRoutes(BuildContext context, SecurityProject project, ScanPolicy policy, List<RouteObservation> routes) async {
  if (routes.isEmpty) return false;
  final confirmed = await showDialog<bool>(context: context, builder: (context) => AlertDialog(
    title: const LText('Save observed routes?'),
    content: const LText('Only scoped route paths and source labels are saved locally. Paths may contain sensitive identifiers. Review them before saving.'),
    actions: [
      TextButton(onPressed: () => Navigator.pop(context, false), child: const LText('Cancel')),
      FilledButton(onPressed: () => Navigator.pop(context, true), child: const LText('Save')),
    ],
  ));
  if (confirmed != true || !context.mounted) return false;
  try {
    await (await routeRepository()).append(project, policy, routes);
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('Routes saved.')));
    return true;
  } catch (_) {
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('Could not save routes.')));
    return false;
  }
}

class SavedRoutesScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  final AuthProfile? auth;
  const SavedRoutesScreen({super.key, required this.project, required this.policy, this.auth});
  @override
  State<SavedRoutesScreen> createState() => _SavedRoutesScreenState();
}

class _SavedRoutesScreenState extends State<SavedRoutesScreen> {
  List<RouteObservation> routes = [];
  String filter = '', search = '';
  bool busy = true;
  String? error;

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    try {
      final found = await (await routeRepository()).load(widget.project, widget.policy);
      if (mounted) setState(() { routes = found; error = null; });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not load saved routes.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> clear() async {
    final confirmed = await showDialog<bool>(context: context, builder: (context) => AlertDialog(
      title: const LText('Clear saved routes?'),
      content: const LText('This removes the saved route list for this project only. Scan history and identities are unchanged.'),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const LText('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, true), child: const LText('Clear')),
      ],
    ));
    if (confirmed != true || !mounted) return;
    setState(() => busy = true);
    try {
      await (await routeRepository()).save(widget.project, widget.policy, []);
      if (mounted) setState(() { routes = []; filter = ''; error = null; });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not save routes.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final shown = routes.where((r) => (filter.isEmpty || r.source == filter) &&
      r.url.toString().toLowerCase().contains(search.trim().toLowerCase())).toList();
    return Scaffold(
      appBar: AppBar(title: const LText('Saved route inventory'), actions: [
        IconButton(tooltip: tr(context, 'Clear'), onPressed: busy || routes.isEmpty ? null : clear, icon: const Icon(Icons.delete_outline)),
      ]),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        const LText('Only explicitly saved in-scope routes are shown. Query parameters are missing. Opening the inspector never sends a request automatically.'),
        TextField(onChanged: (v) => setState(() => search = v), decoration: const InputDecoration(label: LText('Search routes'))),
        DropdownButtonFormField<String>(
          key: ValueKey(filter), initialValue: filter, decoration: const InputDecoration(label: LText('Source / method')),
          items: [const DropdownMenuItem(value: '', child: LText('All sources')),
            for (final source in routes.map((r) => r.source).toSet()) DropdownMenuItem(value: source, child: Text(source))],
          onChanged: busy ? null : (value) => setState(() => filter = value ?? ''),
        ),
        if (busy) const LinearProgressIndicator(),
        if (error != null) LText(error!),
        Text('${uiNumber(context, shown.length)} ${tr(context, 'Routes')}'),
        for (final route in shown) ListTile(
          title: SelectableText(route.url.toString()),
          subtitle: Text(route.source),
          trailing: RouteRepository.canOpenInspector(route) ? IconButton(
            tooltip: tr(context, 'Open request inspector'), icon: const Icon(Icons.http),
            onPressed: () {
              final auth = widget.auth;
              Navigator.of(context).push(MaterialPageRoute(builder: (_) => ManualRequestScreen(
                project: widget.project, target: route.url, policy: widget.policy,
                auth: auth != null && SecurityProject.sameOrigin(auth.target, route.url) ? auth : null,
                initialMethod: route.source == 'HEAD' ? 'HEAD' : 'GET',
              )));
            },
          ) : null,
        ),
      ]),
    );
  }
}
