import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'brand.dart';
import 'tools_screen.dart';
import 'manual_request_screen.dart';
import 'core/history.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/project_storage.dart';

import 'core/project.dart';
import 'core/passive_scan.dart';
import 'core/fingerprint.dart';
import 'core/auth.dart';
import 'core/auth_vault.dart';
import 'auth_dialog.dart';
import 'core/crawler.dart';
import 'core/scan_policy.dart';
import 'scan_policy_dialog.dart';
import 'access_check_screen.dart';
import 'oauth_dialog.dart';
import 'core/oauth_flow.dart';

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
        appBar: AppBar(title: const Row(children: [OdinLogo(size: 34), SizedBox(width: 10), Text('Odin Security')]), actions: [IconButton(tooltip: 'Offline utilities', icon: const Icon(Icons.build_outlined), onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const OfflineToolsScreen())))]),
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
  ScanPolicy policy = ScanPolicy();
  bool loadingPolicy = true;
  String? policyError;
  final vault = AuthVault();
  List<ScanRecord> history = [];
  bool loadingHistory = true;
  String? historyError;

  Future<HistoryRepository> _historyRepo() async => HistoryRepository(PreferencesStorage(await SharedPreferences.getInstance()));

  Future<void> loadHistory() async {
    try {
      final records = await (await _historyRepo()).load(widget.project.id);
      if (mounted) setState(() => history = records);
    } catch (_) {
      if (mounted) setState(() => historyError = 'Could not load scan history.');
    } finally {
      if (mounted) setState(() => loadingHistory = false);
    }
  }

  Future<void> record(ScanRecord item) async {
    try {
      final updated = await (await _historyRepo()).append(widget.project.id, item);
      if (mounted) setState(() => history = updated);
    } catch (_) {
      if (mounted) setState(() => historyError = 'Could not save scan history.');
    }
  }

  List<AuthProfile> profiles = [];
  String selectedProfile = '';
  AuthProfile? get auth {
    for (final profile in profiles) {
      if (profile.name == selectedProfile && SecurityProject.sameOrigin(profile.target, target)) return profile;
    }
    return null;
  }
  late Uri target;
  bool loadingAuth = true;

  @override
  void initState() {
    super.initState();
    target = widget.project.startUrl;
    loadAuth();
    loadHistory();
    loadPolicy();
  }

  Future<ScanPolicyRepository> _policyRepo() async => ScanPolicyRepository(PreferencesStorage(await SharedPreferences.getInstance()));

  Future<void> loadPolicy() async {
    try {
      final loaded = await (await _policyRepo()).load(widget.project.id);
      if (mounted) setState(() { policy = loaded; policyError = null; });
    } catch (_) {
      if (mounted) setState(() => policyError = 'Could not load scan policy; scanning is disabled.');
    } finally {
      if (mounted) setState(() => loadingPolicy = false);
    }
  }

  Future<void> editPolicy() async {
    final next = await showDialog<ScanPolicy>(context: context, builder: (_) => ScanPolicyDialog(policy: policy));
    if (next == null || !mounted) return;
    setState(() => loadingPolicy = true);
    try {
      await (await _policyRepo()).save(widget.project.id, next);
      if (mounted) setState(() { policy = next; policyError = null; authorized = false; });
    } catch (_) {
      if (mounted) setState(() => policyError = 'Could not save scan policy.');
    } finally {
      if (mounted) setState(() => loadingPolicy = false);
    }
  }

  Future<void> loadAuth() async {
    try {
      final values = await vault.loadProfiles(widget.project.id);
      if (mounted) setState(() { profiles = values; selectedProfile = ''; });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not load authentication profile.');
    } finally {
      if (mounted) setState(() => loadingAuth = false);
    }
  }

  Future<void> editAuth({bool add = false}) async {
    final current = add ? null : auth;
    final value = await showDialog<AuthProfile>(context: context, builder: (_) => AuthDialog(project: widget.project, existing: current));
    if (value == null || !mounted) return;
    setState(() { loadingAuth = true; error = null; });
    try {
      final updated = [...profiles.where((p) => !identical(p, current)), value];
      await vault.saveProfiles(widget.project.id, updated);
      if (mounted) setState(() { profiles = updated; selectedProfile = SecurityProject.sameOrigin(value.target, target) ? value.name : ''; authorized = false; });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not save profile. Check that its name is unique.');
    } finally {
      if (mounted) setState(() => loadingAuth = false);
    }
  }

  Future<void> addOAuth() async {
    final value = await showDialog<AuthProfile>(context: context, builder: (_) => OAuthDialog(project: widget.project, target: target));
    if (value == null || !mounted) return;
    setState(() => loadingAuth = true);
    try {
      final updated = [...profiles, value];
      await vault.saveProfiles(widget.project.id, updated);
      if (mounted) setState(() { profiles = updated; selectedProfile = value.name; authorized = false; });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not save OAuth profile. Use a unique identity name.');
    } finally {
      if (mounted) setState(() => loadingAuth = false);
    }
  }

  Future<AuthProfile?> prepareAuth({bool forceRefresh = false}) async {
    final current = auth;
    final grant = current?.oauth;
    if (current == null || grant == null) return current;
    if (!forceRefresh && !grant.needsRefresh(DateTime.now())) return current;
    if (grant.refreshToken.isEmpty) {
      if (grant.expired(DateTime.now()) || forceRefresh) throw StateError('OAuth sign-in is required again.');
      return current;
    }
    final refreshed = await OAuthFlow().refresh(current);
    final updated = profiles.map((p) => identical(p, current) ? refreshed : p).toList();
    await vault.saveProfiles(widget.project.id, updated);
    if (mounted) setState(() => profiles = updated);
    return refreshed;
  }

  Future<void> refreshOAuth() async {
    if (busy || auth?.oauth == null) return;
    setState(() { loadingAuth = true; error = null; });
    try {
      await prepareAuth(forceRefresh: true);
      if (mounted) setState(() => authorized = false);
    } catch (_) {
      if (mounted) setState(() => error = 'OAuth refresh failed. Sign in again with a valid public-client registration.');
    } finally {
      if (mounted) setState(() => loadingAuth = false);
    }
  }

  Future<void> removeAuth() async {
    final current = auth;
    if (current == null) return;
    final confirmed = await showDialog<bool>(context: context, builder: (context) => AlertDialog(
      title: const Text('Delete authentication profile?'),
      content: Text(current.name),
      actions: [TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')), FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Delete'))],
    ));
    if (confirmed != true || !mounted) return;
    setState(() => loadingAuth = true);
    try {
      final updated = profiles.where((p) => !identical(p, current)).toList();
      await vault.saveProfiles(widget.project.id, updated);
      if (mounted) setState(() { profiles = updated; selectedProfile = ''; authorized = false; });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not delete profile.');
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
    if (!authorized || busy || loadingPolicy || policyError != null || !policy.permits(target)) return;
    final flag = CancellationFlag();
    setState(() { busy = true; result = null; crawlResult = null; error = null; visited = 0; cancellation = flag; });
    try {
      final selected = await prepareAuth();
      if (flag.cancelled) return;
      final data = await SiteCrawler().run(widget.project, target, authorized: authorized, cancellation: flag, policy: policy, auth: selected, onProgress: (n) { if (mounted) setState(() => visited = n); });
      if (mounted) {
        setState(() => crawlResult = data);
        await record(ScanRecord.fromPages(data.pages, failedCount: data.failedCount, cancelled: data.cancelled));
      }
    } catch (_) {
      if (mounted) setState(() => error = 'Could not finish the assessment. Check authentication and scope.');
    } finally {
      if (mounted) setState(() { busy = false; cancellation = null; });
    }
  }
  String? error;

  Future<void> scan() async {
    if (!authorized || busy || loadingPolicy || policyError != null || !policy.permits(target)) return;
    setState(() { busy = true; result = null; crawlResult = null; error = null; });
    try {
      final selected = await prepareAuth();
      final data = await PassiveScanner().scan(widget.project, authorized: authorized, target: target, auth: selected);
      if (mounted) {
        setState(() => result = data);
        await record(ScanRecord.fromPages([data]));
      }
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
        OutlinedButton.icon(onPressed: busy || loadingPolicy ? null : editPolicy, icon: const Icon(Icons.tune), label: Text('Scan limits: ${policy.maxPages} pages / ${policy.delayMs} ms')),
        if (policyError != null) Text(policyError!),
        if (!policy.permits(target)) const Text('The selected URL is excluded from scanning.'),
        OutlinedButton.icon(onPressed: busy || loadingAuth || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => AccessCheckScreen(project: widget.project, target: target, profiles: profiles, policy: policy))), icon: const Icon(Icons.people_outline), label: const Text('Compare test account access')),
        OutlinedButton.icon(onPressed: busy || loadingAuth ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ManualRequestScreen(project: widget.project, target: target, auth: auth))), icon: const Icon(Icons.http), label: const Text('Request inspector')),
        OutlinedButton.icon(onPressed: busy ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const InventoryScreen())), icon: const Icon(Icons.description_outlined), label: const Text('Import Swagger / OpenAPI')),
        DropdownButtonFormField<Uri>(initialValue: target, isExpanded: true, decoration: const InputDecoration(labelText: 'Target'), items: widget.project.targets.toSet().map((u) => DropdownMenuItem(value: u, child: Text(u.toString(), overflow: TextOverflow.ellipsis))).toList(), onChanged: busy ? null : (value) => setState(() { target = value!; selectedProfile = ''; authorized = false; result = null; crawlResult = null; })),
        DropdownButtonFormField<String>(
          key: ValueKey('auth.${target.origin}.$selectedProfile'),
          initialValue: selectedProfile,
          decoration: const InputDecoration(labelText: 'Test identity'),
          items: [const DropdownMenuItem(value: '', child: Text('No authentication')), ...profiles.where((p) => SecurityProject.sameOrigin(p.target, target)).map((p) => DropdownMenuItem(value: p.name, child: Text(p.name)))],
          onChanged: busy || loadingAuth ? null : (value) => setState(() { selectedProfile = value ?? ''; authorized = false; result = null; crawlResult = null; }),
        ),
        Wrap(spacing: 8, children: [
          OutlinedButton.icon(onPressed: busy || loadingAuth ? null : () => editAuth(add: true), icon: const Icon(Icons.person_add), label: const Text('Add identity')),
          OutlinedButton.icon(onPressed: busy || loadingAuth || target.scheme != 'https' ? null : addOAuth, icon: const Icon(Icons.login), label: const Text('Add OAuth identity')),
          if (auth != null && auth!.oauth == null) OutlinedButton(onPressed: busy || loadingAuth ? null : () => editAuth(), child: const Text('Edit')),
          if (auth?.oauth != null) OutlinedButton(onPressed: busy || loadingAuth || auth!.oauth!.refreshToken.isEmpty ? null : refreshOAuth, child: const Text('Refresh OAuth token')),
          if (auth != null) OutlinedButton(onPressed: busy || loadingAuth ? null : removeAuth, child: const Text('Delete')),
        ]),
        if (auth != null && auth!.validationUrl.isEmpty) const Text('Session not independently verified. Configure a protected validation URL for reliable authenticated scanning.'),
        CheckboxListTile(
          title: const Text('I own this target or have permission to assess it.'),
          value: authorized,
          onChanged: busy ? null : (value) => setState(() => authorized = value ?? false),
        ),
        FilledButton.icon(onPressed: authorized && !busy && !loadingAuth && !loadingHistory && !loadingPolicy && policyError == null && policy.permits(target) ? scan : null, icon: const Icon(Icons.search), label: const Text('Identify technologies')),
        FilledButton.tonalIcon(onPressed: authorized && !busy && !loadingAuth && !loadingPolicy && policyError == null && policy.permits(target) ? crawl : null, icon: const Icon(Icons.account_tree_outlined), label: Text('Assess linked pages (up to ${policy.maxPages})')),
        if (busy) const LinearProgressIndicator(),
        if (busy && cancellation != null) OutlinedButton(onPressed: cancellation!.cancel, child: Text('Stop ($visited visited)')),
        if (crawlResult != null) ...[
          Text('Pages: ${crawlResult!.pages.length} · Failed: ${crawlResult!.failedCount} · ${crawlResult!.stopReason}'),
          for (final page in crawlResult!.pages) ExpansionTile(title: Text(page.url.toString()), subtitle: Text('HTTP ${page.statusCode} · ${page.findings.length} observations'), children: [
            for (final finding in page.findings) ListTile(title: Text(finding.title), subtitle: Text(finding.remediation), trailing: Text(finding.severity.name)),
          ]),
        ],
        if (error != null) Text(error!),
        const Divider(),
        const Text('Scan history'),
        if (loadingHistory) const LinearProgressIndicator(),
        if (historyError != null) Text(historyError!),
        for (final item in history) ListTile(
          title: Text(item.finishedAt.toLocal().toString().split('.').first),
          subtitle: Text('${item.pages.length} pages · ${item.observationCount} observations'),
          trailing: IconButton(tooltip: 'Copy sanitized JSON report', icon: const Icon(Icons.copy), onPressed: () async {
            await Clipboard.setData(ClipboardData(text: item.exportJson()));
            if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Report copied.')));
          }),
        ),
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
