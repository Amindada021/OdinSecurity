import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/project_storage.dart';

import 'core/project.dart';
import 'core/passive_scan.dart';
import 'core/fingerprint.dart';
import 'core/auth.dart';
import 'core/auth_vault.dart';
import 'auth_dialog.dart';
import 'core/crawler.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final repository = ProjectRepository(PreferencesStorage(await SharedPreferences.getInstance()));
  runApp(OdinSecurityApp(repository: repository));
}

class OdinSecurityApp extends StatelessWidget {
  final ProjectRepository repository;
  const OdinSecurityApp({super.key, required this.repository});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Odin Security',
        theme: ThemeData(colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xff22c5a0), brightness: Brightness.dark), useMaterial3: true),
        home: ProjectScreen(repository: repository),
      );
}

class ProjectScreen extends StatefulWidget {
  final ProjectRepository repository;
  const ProjectScreen({super.key, required this.repository});
  @override
  State<ProjectScreen> createState() => _ProjectScreenState();
}

class _ProjectScreenState extends State<ProjectScreen> {
  final projects = <SecurityProject>[];
  bool loading = true;
  bool saving = false;
  String? loadError;

  @override
  void initState() {
    super.initState();
    loadProjects();
  }

  Future<void> loadProjects() async {
    setState(() { loading = true; loadError = null; });
    try {
      final existing = await widget.repository.load();
      if (mounted) setState(() { projects.clear(); projects.addAll(existing); });
    } catch (_) {
      if (mounted) setState(() => loadError = 'Could not read stored projects. Existing data was not overwritten.');
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  Future<void> addProject() async {
    final project = await showDialog<SecurityProject>(
      context: context,
      builder: (_) => const CreateProjectDialog(),
    );
    if (project == null || !mounted) return;
    setState(() => saving = true);
    try {
      await widget.repository.save([...projects, project]);
      if (mounted) setState(() => projects.add(project));
    } catch (_) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Could not save project.')));
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Odin Security')),
        floatingActionButton: FloatingActionButton.extended(onPressed: loading || saving || loadError != null ? null : addProject, icon: const Icon(Icons.add), label: const Text('New project')),
        body: loading ? const Center(child: CircularProgressIndicator()) : loadError != null ? Center(child: TextButton(onPressed: loadProjects, child: Text(loadError!))) : projects.isEmpty
            ? const Center(child: Padding(padding: EdgeInsets.all(24), child: Text('Create a project to assess an authorized website.')))
            : ListView.builder(
                itemCount: projects.length,
                itemBuilder: (context, index) {
                  final p = projects[index];
                  return ListTile(
                    leading: const Icon(Icons.shield_outlined),
                    title: Text(p.name),
                    subtitle: Text(p.startUrl.toString()),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ScanScreen(project: p))),
                  );
                },
              ),
      );
}

class CreateProjectDialog extends StatefulWidget {
  const CreateProjectDialog({super.key});
  @override
  State<CreateProjectDialog> createState() => _CreateProjectDialogState();
}

class _CreateProjectDialogState extends State<CreateProjectDialog> {
  final name = TextEditingController();
  final url = TextEditingController();
  final api = TextEditingController();
  String? error;
  @override
  void dispose() {
    name.dispose();
    url.dispose();
    api.dispose();
    super.dispose();
  }

  void submit() {
    try {
      Navigator.of(context).pop(SecurityProject(name: name.text, url: url.text, additionalUrls: api.text.trim().isEmpty ? [] : [api.text]));
    } on FormatException catch (e) {
      setState(() => error = e.message);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: const Text('New security project'),
        content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(controller: name, decoration: const InputDecoration(labelText: 'Project name')),
          TextField(controller: url, keyboardType: TextInputType.url, decoration: const InputDecoration(labelText: 'Website URL', hintText: 'https://example.test')),
          TextField(controller: api, keyboardType: TextInputType.url, decoration: const InputDecoration(labelText: 'API URL (optional)')),
          if (error != null) Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
        ])),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
          FilledButton(onPressed: submit, child: const Text('Create')),
        ],
      );
}

class ScanScreen extends StatefulWidget {
  final SecurityProject project;
  const ScanScreen({super.key, required this.project});
  @override
  State<ScanScreen> createState() => _ScanScreenState();
}

class _ScanScreenState extends State<ScanScreen> {
  bool authorized = false;
  final vault = AuthVault();
  AuthProfile? auth;
  late Uri target;
  bool loadingAuth = true;

  @override
  void initState() {
    super.initState();
    target = widget.project.startUrl;
    loadAuth();
  }

  Future<void> loadAuth() async {
    try {
      final value = await vault.load(widget.project.id);
      if (mounted) setState(() => auth = value);
    } catch (_) {
      if (mounted) setState(() => error = 'Could not load authentication profile.');
    } finally {
      if (mounted) setState(() => loadingAuth = false);
    }
  }

  Future<void> editAuth() async {
    final value = await showDialog<AuthProfile>(context: context, builder: (_) => AuthDialog(project: widget.project, existing: auth));
    if (value == null || !mounted) return;
    setState(() => loadingAuth = true);
    try {
      if (value.mode == AuthMode.none) { await vault.clear(widget.project.id); }
      else { await vault.save(widget.project.id, value); }
      if (mounted) setState(() => auth = value.mode == AuthMode.none ? null : value);
    } catch (_) {
      if (mounted) setState(() => error = 'Could not update the secure vault.');
    } finally {
      if (mounted) setState(() => loadingAuth = false);
    }
  }
  bool busy = false;
  PassiveScanResult? result;
  CrawlResult? crawlResult;
  CancellationFlag? cancellation;
  int visited = 0;

  @override
  void dispose() {
    cancellation?.cancel();
    super.dispose();
  }

  Future<void> crawl() async {
    if (!authorized || busy) return;
    final flag = CancellationFlag();
    setState(() { busy = true; result = null; crawlResult = null; error = null; visited = 0; cancellation = flag; });
    try {
      final data = await SiteCrawler().run(widget.project, target, authorized: authorized, cancellation: flag, auth: auth != null && SecurityProject.sameOrigin(auth!.target, target) ? auth : null, onProgress: (n) { if (mounted) setState(() => visited = n); });
      if (mounted) setState(() => crawlResult = data);
    } catch (_) {
      if (mounted) setState(() => error = 'Could not finish the assessment. Check authentication and scope.');
    } finally {
      if (mounted) setState(() { busy = false; cancellation = null; });
    }
  }
  String? error;

  Future<void> scan() async {
    if (!authorized || busy) return;
    setState(() { busy = true; result = null; crawlResult = null; error = null; });
    try {
      final data = await PassiveScanner().scan(widget.project, authorized: authorized, target: target, auth: auth != null && SecurityProject.sameOrigin(auth!.target, target) ? auth : null);
      if (mounted) setState(() => result = data);
    } catch (_) {
      if (mounted) setState(() => error = 'Could not complete the request. Check the URL, connection and TLS.');
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final data = result;
    return Scaffold(
      appBar: AppBar(title: Text(widget.project.name)),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Text(widget.project.startUrl.toString(), style: Theme.of(context).textTheme.titleMedium),
        const Text('Technology fingerprint · Scoped request · No redirects'),
        DropdownButtonFormField<Uri>(initialValue: target, isExpanded: true, decoration: const InputDecoration(labelText: 'Target'), items: widget.project.targets.toSet().map((u) => DropdownMenuItem(value: u, child: Text(u.toString(), overflow: TextOverflow.ellipsis))).toList(), onChanged: busy ? null : (value) => setState(() { target = value!; authorized = false; result = null; })),
        OutlinedButton.icon(onPressed: busy || loadingAuth ? null : editAuth, icon: const Icon(Icons.lock_outline), label: Text(auth == null ? 'Configure authentication' : 'Authentication: ${auth!.mode.name}')),
        if (auth != null && !SecurityProject.sameOrigin(auth!.target, target)) const Text('This target is a different origin. The saved credentials will not be sent.'),
        CheckboxListTile(
          title: const Text('I own this target or have permission to assess it.'),
          value: authorized,
          onChanged: busy ? null : (value) => setState(() => authorized = value ?? false),
        ),
        FilledButton.icon(onPressed: authorized && !busy && !loadingAuth ? scan : null, icon: const Icon(Icons.search), label: const Text('Identify technologies')),
        FilledButton.tonalIcon(onPressed: authorized && !busy && !loadingAuth ? crawl : null, icon: const Icon(Icons.account_tree_outlined), label: const Text('Assess linked pages (up to 12)')),
        if (busy) const LinearProgressIndicator(),
        if (busy && cancellation != null) OutlinedButton(onPressed: cancellation!.cancel, child: Text('Stop ($visited visited)')),
        if (crawlResult != null) ...[
          Text('Pages: ${crawlResult!.pages.length} · Failed: ${crawlResult!.failedCount}'),
          for (final page in crawlResult!.pages) ExpansionTile(title: Text(page.url.toString()), subtitle: Text('HTTP ${page.statusCode} · ${page.findings.length} observations'), children: [
            for (final finding in page.findings) ListTile(title: Text(finding.title), subtitle: Text(finding.remediation), trailing: Text(finding.severity.name)),
          ]),
        ],
        if (error != null) Text(error!),
        if (data != null) ...[
          const SizedBox(height: 16),
          Text('HTTP ${data.statusCode}'),
          if (data.statusCode == 401 || data.statusCode == 403) const Text('Access was not validated. Check authentication and permissions.'),
          if (data.redirectNotFollowed) const Text('Redirect not followed. Review the destination before adding it to scope.'),
          if (data.bodyTruncated) const Text('Response body was truncated; coverage is limited.'),
          const Divider(),
          Text('Security observations (${data.findings.length})'),
          for (final finding in data.findings) ListTile(title: Text(finding.title), subtitle: Text(finding.remediation), trailing: Text(finding.severity.name)),
          for (final layer in TechnologyLayer.values) ...[
            const Divider(),
            Text(layer.name.toUpperCase(), style: Theme.of(context).textTheme.titleSmall),
            if (!data.technologies.any((f) => f.layer == layer)) const Text('Unknown — insufficient evidence'),
            for (final finding in data.technologies.where((f) => f.layer == layer))
              ListTile(title: Text(finding.name), subtitle: Text(finding.evidence), trailing: Text(finding.confidence.name)),
          ],
        ],
      ]),
    );
  }
}
