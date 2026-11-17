import 'dart:async';
import 'package:flutter/material.dart';
import 'localized.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'core/ui_preferences.dart';
import 'package:flutter/services.dart';
import 'brand.dart';
import 'scan_terminal.dart';
import 'tools_screen.dart';
import 'manual_request_screen.dart';
import 'core/history.dart';
import 'report_screen.dart';
import 'spa_inventory_screen.dart';
import 'saved_routes_screen.dart';
import 'traffic_logger_screen.dart';
import 'browser_traffic_screen.dart';
import 'tls_audit_screen.dart';
import 'cors_audit_screen.dart';
import 'regression_audit_screen.dart';
import 'websocket_inventory_screen.dart';
import 'live_websocket_screen.dart';
import 'tunnel_screen.dart';
import 'session_check_screen.dart';
import 'assessment_queue_screen.dart';
import 'scheduled_check_screen.dart';
import 'configuration_review_screen.dart';
import 'representation_matrix_screen.dart';
import 'har_response_review_screen.dart';
import 'lab_collector_review_screen.dart';
import 'external_findings_screen.dart';
import 'core/scheduled_check.dart';
import 'review_organizer_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/project_storage.dart';
import 'core/quick_scan_preferences.dart';

import 'core/project.dart';
import 'core/passive_scan.dart';
import 'core/security_checks.dart';
import 'core/quick_scan_credential.dart';
import 'quick_api_login_dialog.dart';
import 'core/browser_login_policy.dart';
import 'browser_login_screen.dart';
import 'finding_cards.dart';
import 'core/fingerprint.dart';
import 'core/auth.dart';
import 'core/auth_vault.dart';
import 'auth_dialog.dart';
import 'core/crawler.dart';
import 'core/discovery.dart';
import 'core/crawl_checkpoint.dart';
import 'core/custom_rules.dart';
import 'core/metadata_program_settings.dart';
import 'custom_rules_screen.dart';
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

class OdinSecurityApp extends StatefulWidget {
  final ProjectRepository repository;
  const OdinSecurityApp({super.key, required this.repository});
  @override
  State<OdinSecurityApp> createState() => _OdinSecurityAppState();
}

class _OdinSecurityAppState extends State<OdinSecurityApp> {
  UiPreferences preferences = const UiPreferences();
  bool saving = false, ready = false;
  late final UiPreferencesRepository storage = UiPreferencesRepository(widget.repository.storage);

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    try {
      final value = await storage.load();
      if (mounted) setState(() => preferences = value);
    } catch (_) {
      // Corrupt or unavailable preferences do not prevent opening the app.
    } finally {
      if (mounted) setState(() => ready = true);
    }
  }

  Future<bool> select(String choice) async {
    if (!ready || saving) return false;
    final next = ['en', 'fa'].contains(choice)
      ? preferences.copyWith(language: choice) : preferences.copyWith(theme: choice);
    setState(() => saving = true);
    try {
      await storage.save(next);
      if (mounted) setState(() => preferences = next);
      return true;
    } catch (_) {
      return false;
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  ThemeData theme(Brightness brightness) {
    final scheme = ColorScheme.fromSeed(seedColor: const Color(0xff12a89d), brightness: brightness).copyWith(primary: brightness == Brightness.dark ? const Color(0xff62f6b2) : const Color(0xff006b50));
    return ThemeData(
      colorScheme: scheme,
      useMaterial3: true,
      scaffoldBackgroundColor: brightness == Brightness.dark ? const Color(0xff091311) : const Color(0xfff3f8f6),
      cardTheme: CardThemeData(elevation: 0, shape: RoundedRectangleBorder(
        side: BorderSide(color: scheme.outlineVariant), borderRadius: BorderRadius.circular(20))),
      inputDecorationTheme: InputDecorationTheme(filled: true, border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14), borderSide: BorderSide.none)),
      filledButtonTheme: FilledButtonThemeData(style: FilledButton.styleFrom(
        minimumSize: const Size(0, 48), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)))),
    );
  }
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Odin Security',
    locale: Locale(preferences.language),
    supportedLocales: const [Locale('en'), Locale('fa')],
    localizationsDelegates: GlobalMaterialLocalizations.delegates,
    theme: theme(Brightness.light), darkTheme: theme(Brightness.dark),
    themeMode: switch (preferences.theme) {
      'light' => ThemeMode.light, 'system' => ThemeMode.system, _ => ThemeMode.dark,
    },
    home: ProjectScreen(repository: widget.repository, preferences: preferences, settingsEnabled: ready && !saving, onPreference: select),
  );
}

class ProjectScreen extends StatefulWidget {
  final ProjectRepository repository;
  final UiPreferences preferences;
  final bool settingsEnabled;
  final Future<bool> Function(String choice) onPreference;
  const ProjectScreen({super.key, required this.repository, required this.preferences, required this.settingsEnabled, required this.onPreference});
  @override
  State<ProjectScreen> createState() => _ProjectScreenState();
}

class _ProjectScreenState extends State<ProjectScreen> {
  final projects = <SecurityProject>[];
  bool loading = true;
  bool saving = false;
  String? loadError;
  String search = '';

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
      if (mounted) {
        setState(() => projects.add(project));
        await Navigator.of(context).push(MaterialPageRoute(builder: (_) => ScanScreen(project: project)));
      }
    } catch (_) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('Could not save project.')));
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  Future<void> editProject(SecurityProject current) async {
    if (loading || saving) return;
    final updated = await showDialog<SecurityProject>(
      context: context, builder: (_) => CreateProjectDialog(existing: current),
    );
    if (updated == null || !mounted) return;
    setState(() => saving = true);
    try {
      final next = projects.map((p) => p.id == current.id ? updated : p).toList();
      await ScheduledCheck.cancelProject(current.id);
      await widget.repository.save(next);
      if (mounted) setState(() { projects.clear(); projects.addAll(next); });
    } catch (_) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('Could not save project changes.')));
    } finally {
      if (mounted) setState(() => saving = false);
    }
  }

  List<SecurityProject> get filteredProjects {
    final term = search.trim().toLowerCase();
    if (term.isEmpty) return projects;
    return projects.where((p) => p.name.toLowerCase().contains(term) ||
      p.targets.any((u) => u.toString().toLowerCase().contains(term))).toList();
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Row(children: [OdinLogo(size: 34), SizedBox(width: 10), Text('Odin Security')]), actions: [PopupMenuButton<String>(
          tooltip: tr(context, 'Settings'), enabled: widget.settingsEnabled,
          onSelected: (choice) async {
            final saved = await widget.onPreference(choice);
            if (!saved && context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('Preferences could not be saved.')));
          },
          itemBuilder: (_) => [
            CheckedPopupMenuItem(value: 'en', checked: widget.preferences.language == 'en', child: const LText('English')),
            CheckedPopupMenuItem(value: 'fa', checked: widget.preferences.language == 'fa', child: const LText('Persian')),
            const PopupMenuDivider(),
            CheckedPopupMenuItem(value: 'light', checked: widget.preferences.theme == 'light', child: const LText('Light theme')),
            CheckedPopupMenuItem(value: 'dark', checked: widget.preferences.theme == 'dark', child: const LText('Dark theme')),
            CheckedPopupMenuItem(value: 'system', checked: widget.preferences.theme == 'system', child: const LText('System theme')),
          ],
        ), IconButton(tooltip: tr(context, 'About Odin Security'), icon: const Icon(Icons.info_outline), onPressed: () => showAboutDialog(context: context, applicationName: 'Odin Security', applicationVersion: '0.83.0+88', applicationIcon: const OdinLogo(size: 48))), IconButton(tooltip: tr(context, 'Offline utilities'), icon: const Icon(Icons.build_outlined), onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const OfflineToolsScreen())))]),
        floatingActionButton: FloatingActionButton.extended(onPressed: loading || saving || loadError != null ? null : addProject, icon: const Icon(Icons.add), label: const LText('New project')),
        body: loading ? const Center(child: CircularProgressIndicator()) : loadError != null ? Center(child: TextButton(onPressed: loadProjects, child: LText(loadError!))) : projects.isEmpty
            ? Center(child: Padding(padding: const EdgeInsets.all(24), child: Column(mainAxisSize: MainAxisSize.min, children: [
                const OdinLogo(size: 82),
                const SizedBox(height: 20),
                LText('Your security workspace', style: Theme.of(context).textTheme.headlineSmall),
                const SizedBox(height: 8),
                const LText('Create a project to assess an authorized website.'),
              ])))
            : Column(children: [
                ListTile(leading: const Icon(Icons.radar), title: const LText('Your security workspace'),
                  trailing: Text(uiNumber(context, projects.length))),
                Padding(padding: const EdgeInsets.all(12), child: TextField(
                  onChanged: (value) => setState(() => search = value),
                  decoration: const InputDecoration(prefixIcon: Icon(Icons.search), label: LText('Search projects or origins')),
                )),
                Expanded(child: filteredProjects.isEmpty
                  ? const Center(child: LText('No matching projects.'))
                  : ListView.builder(
                    itemCount: filteredProjects.length,
                    itemBuilder: (context, index) {
                      final p = filteredProjects[index];
                      return Card(margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6), child: ListTile(
                        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        leading: CircleAvatar(backgroundColor: Theme.of(context).colorScheme.primaryContainer, child: const Icon(Icons.shield_outlined)),
                        title: Text(p.name),
                        subtitle: Text('${p.startUrl}\n${uiNumber(context, p.targets.length)} ${tr(context, 'targets')}'),
                        trailing: IconButton(tooltip: tr(context, 'Edit project'), icon: const Icon(Icons.edit_outlined), onPressed: saving ? null : () => editProject(p)),
                        onTap: saving ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ScanScreen(project: p))),
                      ));
                    },
                  )),
              ]),
      );
}

class CreateProjectDialog extends StatefulWidget {
  final SecurityProject? existing;
  const CreateProjectDialog({super.key, this.existing});
  @override
  State<CreateProjectDialog> createState() => _CreateProjectDialogState();
}

class _CreateProjectDialogState extends State<CreateProjectDialog> {
  final name = TextEditingController();
  final url = TextEditingController();
  final api = TextEditingController();
  String? error;
  @override
  void initState() {
    super.initState();
    final existing = widget.existing;
    if (existing != null) {
      name.text = existing.name;
      url.text = existing.startUrl.toString();
      api.text = existing.additionalUrls.join('\n');
    }
  }
  @override
  void dispose() {
    name.dispose();
    url.dispose();
    api.dispose();
    super.dispose();
  }

  void submit() {
    try {
      final input = url.text.trim();
      final uri = SecurityProject.parseTarget(input.contains('://') ? input : 'https://$input');
      final projectName = name.text.trim().isEmpty ? uri.host : name.text.trim();
      Navigator.of(context).pop(SecurityProject(id: widget.existing?.id, name: projectName, url: uri.toString(), additionalUrls: SecurityProject.parseTargetLines(api.text)));
    } on FormatException catch (e) {
      setState(() => error = e.message);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
        title: LText(widget.existing == null ? 'New security project' : 'Edit security project'),
        content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(controller: url, autofocus: widget.existing == null, keyboardType: TextInputType.url, decoration: const InputDecoration(label: LText('Website URL'), hintText: 'https://example.test')),
              TextField(controller: api, keyboardType: TextInputType.multiline, minLines: 1, maxLines: 4, decoration: const InputDecoration(label: LText('Additional website / API URLs'))),
          if (widget.existing == null) const LText('Only a website address is required. Other settings are optional.'),
          ExpansionTile(
            initiallyExpanded: widget.existing != null,
            title: const LText('Optional project settings'),
            children: [
              TextField(controller: name, decoration: const InputDecoration(label: LText('Project name'))),
            ],
          ),
          if (widget.existing != null) const LText('History and saved identities stay with this project. Only explicitly listed origins may be selected for new scans.'),
          if (error != null) LText(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
        ])),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const LText('Cancel')),
          FilledButton(onPressed: submit, child: LText(widget.existing == null ? 'Create' : 'Save')),
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
  bool advanced = false;
  ScanRecord? quickReport;
  final quickToken = TextEditingController();
  bool quickTokenEnabled = false, quickLoginEnabled = false, quickApiEnabled = false;
  final purchasedMovies = TextEditingController();
  final restrictedMovies = TextEditingController();
  bool quickSaved = false;
  bool quickAllowInsecure = false;
  bool loadingQuickSettings = true;
  String? quickSettingsError;
  Timer? _quickSettingsTimer;
  Future<void> _pendingQuickSettingsSave = Future<void>.value();
  Future<QuickScanPreferencesRepository> _quickSettingsRepository() async =>
      QuickScanPreferencesRepository(PreferencesStorage(await SharedPreferences.getInstance()));

  QuickScanPreferences get quickSettingsSnapshot {
    final rawLogin = quickLoginUrl.text.trim();
    final uri = Uri.tryParse(rawLogin);
    // Never persist query parameters or embedded userinfo (which may hold secrets).
    final safeLogin = uri != null && uri.userInfo.isEmpty
        ? (rawLogin.startsWith('/')
            ? (uri.path.isEmpty ? '/login' : uri.path)
            : uri.replace(query: '', fragment: '').toString())
        : '/login';
    return QuickScanPreferences(
      target: target.toString(),
      method: !quickLoginEnabled ? 'public' : quickSaved ? 'saved' :
          quickApiEnabled ? 'api' : quickTokenEnabled ? 'token' : 'browser',
      loginUrl: safeLogin,
      headerName: quickHeader.text.trim(),
      identityName: quickSaved ? selectedProfile : '',
      delivery: quickDelivery,
    );
  }

  Future<void> loadQuickSettings() async {
    try {
      final saved = await (await _quickSettingsRepository()).load(widget.project.id);
      if (!mounted) return;
      setState(() {
        for (final candidate in widget.project.targets) {
          if (candidate.toString() == saved.target) {
            target = candidate;
            break;
          }
        }
        quickLoginEnabled = saved.method != 'public';
        quickSaved = saved.method == 'saved';
        quickApiEnabled = saved.method == 'api';
        quickTokenEnabled = saved.method == 'token';
        quickLoginUrl.text = saved.loginUrl;
        quickHeader.text = saved.headerName;
        quickDelivery = saved.delivery;
        selectedProfile = saved.identityName;
        quickSettingsError = null;
      });
    } catch (_) {
      if (mounted) setState(() => quickSettingsError = 'Could not load saved quick-scan settings.');
    } finally {
      if (mounted) setState(() => loadingQuickSettings = false);
    }
  }

  void rememberQuickSettings({bool immediate = false}) {
    if (loadingQuickSettings) return;
    _quickSettingsTimer?.cancel();
    if (immediate) {
      _saveQuickSettings();
    } else {
      _quickSettingsTimer = Timer(const Duration(milliseconds: 400), _saveQuickSettings);
    }
  }

  void _saveQuickSettings() {
    final value = quickSettingsSnapshot;
    _pendingQuickSettingsSave = _pendingQuickSettingsSave.then((_) async {
      await (await _quickSettingsRepository()).save(widget.project.id, value);
    }).catchError((Object _) {
      if (mounted) setState(() => quickSettingsError = 'Could not save quick-scan settings.');
    });
  }

  Future<void> saveQuickCredential() async {
    if (!quickTokenEnabled || quickToken.text.trim().isEmpty ||
        target.scheme != 'https' || loadingAuth || busy) return;
    try {
      final current = QuickScanCredential.parse(target, quickToken.text,
        delivery: quickDelivery, headerName: quickHeader.text.trim());
      if (current == null) throw const FormatException('Missing token.');
      final name = 'Quick credential - ${target.host}';
      final stored = AuthProfile(
        mode: current.mode, target: target, secret: current.secret,
        name: name, cookiePath: current.cookiePath,
        tokenDelivery: current.tokenDelivery, headerName: current.headerName);
      final updated = [
        ...profiles.where((p) => !(p.name == name &&
          SecurityProject.sameOrigin(p.target, target))),
        stored,
      ];
      await vault.saveProfiles(widget.project.id, updated);
      if (!mounted) return;
      setState(() {
        profiles = updated; selectedProfile = name;
        quickSaved = true; quickTokenEnabled = false; quickApiEnabled = false;
        quickToken.clear(); authorized = false; error = null;
      });
      rememberQuickSettings(immediate: true);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: LText('Credential saved in encrypted storage for this project.')));
    } catch (_) {
      if (mounted) setState(() => error = 'Could not save credential securely.');
    }
  }
  bool get quickAuthTransportAllowed => target.scheme == 'https' || (target.scheme == 'http' && quickAllowInsecure);
  TokenDelivery quickDelivery = TokenDelivery.bearer;
  final quickHeader = TextEditingController(text: 'X-API-Key');
  final quickLoginUrl = TextEditingController(text: '/login');
  ScanPolicy policy = ScanPolicy();
  bool loadingPolicy = true;
  String? policyError;
  final vault = AuthVault();
  List<ScanRecord> history = [];
  bool loadingHistory = true;
  String? historyError;
  CrawlCheckpoint? checkpoint;
  bool loadingCheckpoint = true;
  String? checkpointError;
  Future<CrawlCheckpointRepository> _checkpointRepo() async => CrawlCheckpointRepository(PreferencesStorage(await SharedPreferences.getInstance()));
  Future<void> loadCheckpoint() async {
    try {
      final value = await (await _checkpointRepo()).load(widget.project.id);
      if (mounted) setState(() { checkpoint = value; checkpointError = null; });
    } catch (_) {
      if (mounted) setState(() => checkpointError = 'Could not load saved crawl checkpoint.');
    } finally { if (mounted) setState(() => loadingCheckpoint = false); }
  }
  Future<void> discardCheckpoint() async {
    if (busy || loadingCheckpoint) return;
    final confirmed = await showDialog<bool>(context: context, builder: (context) => AlertDialog(
      title: const LText('Discard saved crawl?'), actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const LText('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, true), child: const LText('Discard saved crawl')),
      ]));
    if (confirmed != true || !mounted) return;
    setState(() => loadingCheckpoint = true);
    try {
      await (await _checkpointRepo()).save(widget.project.id, null);
      if (mounted) setState(() { checkpoint = null; checkpointError = null; authorized = false; });
    } catch (_) { if (mounted) setState(() => checkpointError = 'Could not save crawl checkpoint.'); }
    finally { if (mounted) setState(() => loadingCheckpoint = false); }
  }

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
  String? authLoadError;

  @override
  void initState() {
    super.initState();
    target = widget.project.startUrl;
    loadQuickSettings();
    loadAuth();
    loadHistory();
    loadPolicy();
    loadCheckpoint();
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
      await ScheduledCheck.cancelProject(widget.project.id);
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
      if (mounted) setState(() { profiles = values; });
    } catch (_) {
      if (mounted) setState(() => authLoadError = 'Could not load authentication profile.');
    } finally {
      if (mounted) setState(() => loadingAuth = false);
    }
  }

  Future<void> importIdentity() async {
    setState(() => loadingAuth = true);
    try {
      final repository = ProjectRepository(PreferencesStorage(await SharedPreferences.getInstance()));
      final matches = <(String, AuthProfile)>[];
      for (final project in await repository.load()) {
        if (project.id == widget.project.id || !project.targets.any((u) => SecurityProject.sameOrigin(u, target))) continue;
        for (final profile in await vault.loadProfiles(project.id)) {
          if (SecurityProject.sameOrigin(profile.target, target)) matches.add((project.name, profile));
        }
      }
      if (!mounted) return;
      if (matches.isEmpty) {
        setState(() => error = 'No saved identity for this origin.');
        return;
      }
      final chosen = await showDialog<AuthProfile>(context: context, builder: (context) => SimpleDialog(
        title: const LText('Reuse project identity'), children: [
          for (final match in matches) ListTile(title: Text(match.$2.name), subtitle: Text(match.$1),
            onTap: () => Navigator.pop(context, match.$2)),
        ]));
      if (chosen == null || !mounted) return;
      final updated = [...profiles, chosen];
      await vault.saveProfiles(widget.project.id, updated);
      if (mounted) setState(() { profiles = updated; selectedProfile = chosen.name; authorized = false; error = null; });
    } catch (_) {
      if (mounted) setState(() => error = 'Could not save profile. Check that its name is unique.');
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
      title: const LText('Delete authentication profile?'),
      content: Text(current.name),
      actions: [TextButton(onPressed: () => Navigator.pop(context, false), child: const LText('Cancel')), FilledButton(onPressed: () => Navigator.pop(context, true), child: const LText('Delete'))],
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
  final terminalLines = <TerminalLine>[];
  void logEvent(String tag, String message, String detail) {
    if (!mounted) return;
    setState(() => terminalLines.add((tag: tag, message: message, detail: detail)));
  }

  @override
  void dispose() {
    cancellation?.cancel();
    _quickSettingsTimer?.cancel();
    if (!loadingQuickSettings) _saveQuickSettings();
    quickToken.dispose();
    purchasedMovies.dispose();
    restrictedMovies.dispose();
    quickLoginUrl.dispose();
    quickHeader.dispose();
    super.dispose();
  }

  String? get quickLoginError {
    if (!quickLoginEnabled || quickSaved || quickTokenEnabled || quickApiEnabled || !quickAuthTransportAllowed) return null;
    try {
      BrowserLoginPolicy.loginUrl(widget.project, target, quickLoginUrl.text, policy.quickDefaults, allowInsecureHttp: quickAllowInsecure);
      return null;
    } on FormatException {
      return 'Enter a permitted HTTPS sign-in URL.';
    }
  }

  Future<void> quickScan() async {
    if (advanced || !authorized || busy || loadingQuickSettings || (quickLoginEnabled && !quickAuthTransportAllowed) || loadingPolicy || loadingHistory ||
        policyError != null || !policy.permits(target)) return;
    rememberQuickSettings(immediate: true);
    final flag = CancellationFlag();
    terminalLines.clear();
    final settings = policy.quickDefaults;
    final selectedTarget = target;
    final movies = <Uri, bool>{};
    if (quickLoginEnabled) {
      try {
        for (final group in [(purchasedMovies.text, true), (restrictedMovies.text, false)]) {
          for (final line in group.$1.split('\n').map((v) => v.trim()).where((v) => v.isNotEmpty)) {
            final url = SecurityProject.parseTarget(selectedTarget.resolve(line).toString());
            if (!LinkDiscovery.safeMediaTarget(selectedTarget, url) || !settings.permits(url) ||
                (movies.containsKey(url) && movies[url] != group.$2)) throw const FormatException();
            movies[url] = group.$2;
          }
        }
        if (movies.length > settings.maxPages) throw const FormatException();
      } on FormatException {
        setState(() => error = 'Check movie URLs, purchase groups and scan limit.');
        return;
      }
    }
    AuthProfile? credential;
    Uri? login;
    final apiLogin = quickLoginEnabled && quickApiEnabled;
    try {
      if (quickLoginEnabled) {
        if (quickTokenEnabled) {
          credential = QuickScanCredential.parse(selectedTarget, quickToken.text, delivery: quickDelivery, headerName: quickHeader.text.trim(), allowInsecureHttp: quickAllowInsecure);
          if (credential == null) throw const FormatException('Missing token.');
        } else if (!quickSaved && !apiLogin) {
          login = BrowserLoginPolicy.loginUrl(widget.project, selectedTarget, quickLoginUrl.text, settings, allowInsecureHttp: quickAllowInsecure);
        }
      }
    } on FormatException {
      setState(() => error = quickTokenEnabled
          ? 'Enter a valid credential for the selected target.'
          : 'Enter a permitted HTTPS sign-in URL.');
      return;
    }
    quickToken.clear();
    setState(() {
      busy = true; result = null; crawlResult = null; quickReport = null;
      error = null; visited = 0; cancellation = flag;
    });
    try {
      var scanStart = selectedTarget;
      if (quickLoginEnabled && quickSaved) {
        credential = await prepareAuth();
        if (credential == null || !mounted || flag.cancelled) return;
      }
      if (apiLogin) {
        credential = await showDialog<AuthProfile>(context: context, builder: (_) => QuickApiLoginDialog(
          project: widget.project, target: selectedTarget, policy: settings, allowInsecureHttp: quickAllowInsecure));
        if (!mounted || credential == null || flag.cancelled) return;
      }
      final browserLogin = login;
      if (browserLogin != null) {
        final captured = await Navigator.of(context).push<BrowserLoginResult>(MaterialPageRoute(
          builder: (_) => BrowserLoginScreen(projectId: widget.project.id, target: selectedTarget, login: browserLogin,
            automatic: true, policy: settings, allowInsecureHttp: quickAllowInsecure)));
        if (!mounted || captured == null || flag.cancelled) return;
        scanStart = captured.start;
        credential = captured.usesToken
          ? AuthProfile(mode: AuthMode.bearer, target: selectedTarget,
              name: 'Automatic browser token', secret: captured.token!,
              tokenDelivery: captured.tokenDelivery, allowInsecureHttp: quickAllowInsecure)
          : AuthProfile(mode: AuthMode.cookie, target: selectedTarget,
              name: 'Automatic browser session', secret: captured.cookieHeader,
              cookiePath: captured.cookiePath, allowInsecureHttp: quickAllowInsecure);
        if (captured.usesToken && captured.rememberCredential &&
            selectedTarget.scheme == 'https') {
          try {
            final name = 'Quick credential - ${selectedTarget.host}';
            final stored = AuthProfile(
              mode: AuthMode.bearer, target: selectedTarget,
              name: name, secret: captured.token!,
              tokenDelivery: captured.tokenDelivery);
            final updated = [
              ...profiles.where((p) => !(p.name == name &&
                  SecurityProject.sameOrigin(p.target, selectedTarget))),
              stored,
            ];
            await vault.saveProfiles(widget.project.id, updated);
            if (mounted) {
              setState(() {
                profiles = updated; selectedProfile = name;
                quickSaved = true; quickTokenEnabled = false; quickApiEnabled = false;
              });
              rememberQuickSettings(immediate: true);
            }
          } catch (_) {
            if (mounted) ScaffoldMessenger.of(context).showSnackBar(
              const SnackBar(content: LText('Token could not be saved; this scan can continue.')));
          }
        }
      }
      // Authentication is scoped to the chosen target; secrets never enter scan preferences.
      final data = await SiteCrawler().run(widget.project, scanStart,
        authorized: true, policy: settings, cancellation: flag, auth: credential, moviePurchases: movies,
        onEvent: logEvent, onProgress: (count) { if (mounted) setState(() => visited = count); });
      if (!mounted) return;
      final report = ScanRecord.fromPages(data.pages, failedCount: data.failedCount, cancelled: data.cancelled, files: data.files);
      setState(() { crawlResult = data; quickReport = report; });
      await record(report);
    } catch (_) {
      if (mounted) setState(() => error = apiLogin
        ? 'API sign-in or scan failed. Check the endpoint, username, password and token response settings.'
        : 'Could not finish the quick scan. Check the URL and connection.');
    } finally {
      if (mounted) setState(() { busy = false; cancellation = null; authorized = false; quickAllowInsecure = false; });
    }
  }

  String quickStatus(String reason) => switch (reason) {
    'cancelled' => 'Scan stopped',
    'rate_limited' => 'Stopped: server request limit reached',
    'server_errors' => 'Stopped: repeated server errors',
    'time_budget' => 'Stopped: time limit reached',
    'page_budget' => 'Completed: page limit reached',
    'authentication_rejected' => 'Stopped: access requires review',
    _ => 'Scan completed',
  };

  Future<void> crawl({bool resume = false}) async {
    if (!authorized || busy || loadingPolicy || loadingCheckpoint || policyError != null || checkpointError != null || !policy.permits(target)) return;
    if (resume ? checkpoint == null : checkpoint != null) return;
    final saved = resume ? checkpoint : null;
    final flag = CancellationFlag();
    terminalLines.clear();
    setState(() { busy = true; result = null; crawlResult = null; error = null; visited = 0; cancellation = flag; });
    try {
      final selected = await prepareAuth();
      if (flag.cancelled) return;
      final storage = PreferencesStorage(await SharedPreferences.getInstance());
      final rules = await CustomRuleRepository(storage).load(widget.project.id);
      final program = (await MetadataProgramRepository(storage).load(widget.project.id)).activeProgram;
      if (flag.cancelled || !mounted) return;
      final repository = await _checkpointRepo();
      final data = await SiteCrawler(scanner: PassiveScanner(customRules: rules, metadataProgram: program)).run(widget.project, target,
        authorized: authorized, cancellation: flag, policy: policy, auth: selected, resumeFrom: saved,
        onCheckpoint: (value) async {
          await repository.save(widget.project.id, value);
          if (mounted) setState(() => checkpoint = value);
        }, onEvent: logEvent, onProgress: (n) { if (mounted) setState(() => visited = n); });
      if (mounted) {
        setState(() => crawlResult = data);
        await record(ScanRecord.fromPages(data.pages, failedCount: data.failedCount, cancelled: data.cancelled, files: data.files));
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
      final storage = PreferencesStorage(await SharedPreferences.getInstance());
      final rules = await CustomRuleRepository(storage).load(widget.project.id);
      final program = (await MetadataProgramRepository(storage).load(widget.project.id)).activeProgram;
      if (!mounted) return;
      final data = await PassiveScanner(customRules: rules, metadataProgram: program).scan(widget.project, authorized: authorized, target: target, auth: selected, permits: policy.permits);
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
      body: busy && cancellation != null ? ScanTerminal(lines: terminalLines, control: cancellation!, pages: visited,
        onToggle: () => setState(() { if (cancellation!.paused) { cancellation!.resume(); } else { cancellation!.pause(); } }),
        onStop: () => setState(() => cancellation!.cancel())) : ListView(padding: const EdgeInsets.all(16), children: [
        SegmentedButton<bool>(
          segments: const [
            ButtonSegment(value: false, label: LText('Automatic scan'), icon: Icon(Icons.flash_on)),
            ButtonSegment(value: true, label: LText('Advanced mode'), icon: Icon(Icons.tune)),
          ],
          selected: {advanced},
          onSelectionChanged: busy || loadingQuickSettings ? null : (selection) {
            setState(() {
              advanced = selection.first; authorized = false;
              quickAllowInsecure = false; quickToken.clear();
              result = null; crawlResult = null; quickReport = null; error = null;
            });
            rememberQuickSettings();
          },
        ),
        const SizedBox(height: 12),
        if (!advanced) ...[
          Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(colors: [Theme.of(context).colorScheme.primaryContainer, Theme.of(context).colorScheme.surfaceContainerHigh]),
              borderRadius: BorderRadius.circular(22)),
            padding: const EdgeInsets.all(18),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              CircleAvatar(backgroundColor: Theme.of(context).colorScheme.primary, foregroundColor: Theme.of(context).colorScheme.onPrimary,
                child: const Icon(Icons.shield_outlined)),
              const SizedBox(width: 12),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                LText('Ready to scan', style: Theme.of(context).textTheme.titleLarge),
                const SizedBox(height: 6),
                const LText('Automatically discover linked pages and review security headers, TLS, web technologies and response configuration.'),
              ])),
            ]),
          ),
          const SizedBox(height: 16),
          if (policyError != null) LText(policyError!),
          if (quickSettingsError != null) LText(quickSettingsError!),
          if (loadingQuickSettings) const LinearProgressIndicator(),
          if (!policy.permits(target)) const LText('The selected URL is excluded from scanning.'),
          DropdownButtonFormField<Uri>(
            key: ValueKey('quick.target.$target'), initialValue: target, isExpanded: true,
            decoration: const InputDecoration(label: LText('Website URL')),
            items: [for (final u in widget.project.targets) DropdownMenuItem(value: u, child: Text(u.toString(), overflow: TextOverflow.ellipsis))],
            onChanged: busy || loadingQuickSettings ? null : (value) {
              if (value == null) return;
              setState(() {
                target = value; authorized = false; quickReport = null; crawlResult = null; error = null;
                quickAllowInsecure = false; quickToken.clear(); selectedProfile = '';
              });
              rememberQuickSettings();
            },
          ),
          const SizedBox(height: 6),
          Row(children: [
            const Icon(Icons.radar, size: 16),
            const SizedBox(width: 8),
            Expanded(child: Text('${tr(context, 'Selected scan target')}: ${target.host}',
              maxLines: 2, overflow: TextOverflow.ellipsis)),
          ]),
          const SizedBox(height: 8),
          SegmentedButton<bool>(
            segments: const [
              ButtonSegment(value: false, icon: Icon(Icons.public), label: LText('Public website')),
              ButtonSegment(value: true, icon: Icon(Icons.lock_outline), label: LText('After sign-in')),
            ],
            selected: {quickLoginEnabled},
            onSelectionChanged: busy || loadingQuickSettings ? null : (selection) {
              setState(() {
                quickLoginEnabled = selection.first;
                quickAllowInsecure = false;
                quickToken.clear();
                authorized = false; error = null;
              });
              rememberQuickSettings();
            },
          ),
          const SizedBox(height: 8),
          if (!quickLoginEnabled && target.scheme == 'http') const ListTile(leading: Icon(Icons.warning_amber), title: LText('HTTP traffic is unencrypted.')),
          if (!quickLoginEnabled)
            const LText('Scan the landing page and public links without signing in.'),
          if (quickLoginEnabled) ...[
            const LText('Choose browser sign-in, direct API sign-in, or enter an existing credential.'),
            if (target.scheme == 'http') CheckboxListTile(
              contentPadding: EdgeInsets.zero,
              title: const LText('Allow insecure HTTP sign-in for this scan'),
              subtitle: const LText('Warning: HTTP sends passwords, tokens and cookies without encryption. Use only on authorized test targets.'),
              value: quickAllowInsecure,
              onChanged: busy ? null : (value) => setState(() {
                quickAllowInsecure = value ?? false; authorized = false; error = null;
                if (!quickAllowInsecure) { quickToken.clear(); quickTokenEnabled = false; quickApiEnabled = false; }
              }),
            ),
            DropdownButtonFormField<String>(
              key: ValueKey('method.$quickApiEnabled.$quickTokenEnabled.$quickSaved'),
              initialValue: quickSaved ? 'saved' : quickApiEnabled ? 'api' : quickTokenEnabled ? 'token' : 'browser',
              isExpanded: true, decoration: const InputDecoration(label: LText('Authentication method')),
              items: const [
                DropdownMenuItem(value: 'browser', child: LText('Browser sign-in')),
                DropdownMenuItem(value: 'api', child: LText('Direct API sign-in')),
                DropdownMenuItem(value: 'token', child: LText('Use existing credential instead')),
                DropdownMenuItem(value: 'saved', child: LText('Test identity')),
              ],
              onChanged: busy || loadingQuickSettings || !quickAuthTransportAllowed ? null : (method) {
                setState(() {
                  quickSaved = method == 'saved'; quickApiEnabled = method == 'api';
                  quickTokenEnabled = method == 'token';
                  quickToken.clear(); authorized = false; error = null;
                });
                rememberQuickSettings();
              },
            ),
            if (quickSaved) ...[
              DropdownButtonFormField<String>(key: ValueKey('saved.$selectedProfile'), initialValue: selectedProfile,
                isExpanded: true, decoration: const InputDecoration(label: LText('Test identity')),
                items: [const DropdownMenuItem(value: '', child: LText('Choose identity')),
                  for (final p in profiles.where((p) => SecurityProject.sameOrigin(p.target, target)))
                    DropdownMenuItem(value: p.name, child: Text(p.name))],
                onChanged: loadingAuth ? null : (value) {
                  setState(() { selectedProfile = value ?? ''; authorized = false; });
                  rememberQuickSettings();
                }),
              Wrap(children: [
                TextButton(onPressed: loadingAuth ? null : () => editAuth(add: true), child: const LText('Add identity')),
                TextButton(onPressed: loadingAuth || target.scheme != 'https' ? null : addOAuth, child: const LText('Add OAuth identity')),
                TextButton(onPressed: loadingAuth ? null : importIdentity, child: const LText('Reuse project identity')),
              ]),
            ],
            if (!quickSaved && !quickTokenEnabled && !quickApiEnabled) ...[
              TextField(
                controller: quickLoginUrl, enabled: !busy && quickAuthTransportAllowed,
                keyboardType: TextInputType.url, autocorrect: false,
                decoration: InputDecoration(prefixIcon: const Icon(Icons.login),
                  label: const LText('Sign-in page URL'), hintText: '/login',
                  errorText: quickLoginError == null ? null : tr(context, quickLoginError!)),
                onChanged: (_) {
                  setState(() { authorized = false; error = null; });
                  rememberQuickSettings();
                },
              ),
              const Padding(padding: EdgeInsets.only(top: 6), child: LText('Enter a login path or full sign-in URL. The scan target stays unchanged. Cookie-based sessions are supported; token-only APIs require API authentication.')),
            ],
          ],
          if (quickLoginEnabled) ExpansionTile(
            leading: const Icon(Icons.movie_outlined), title: const LText('Movie purchase check'),
            children: [
              Text(tr(context, 'Enter full-feature media URLs, one per line. Exclude trailers and free titles.')),
              for (final group in [(purchasedMovies, 'Purchased movies'), (restrictedMovies, 'Unpurchased paid movies')])
                Padding(padding: const EdgeInsets.symmetric(vertical: 6), child: TextField(
                  controller: group.$1, minLines: 1, maxLines: 5, textDirection: TextDirection.ltr,
                  decoration: InputDecoration(label: LText(group.$2)))),
            ]),
          if (quickLoginEnabled && quickTokenEnabled) ...[
            DropdownButtonFormField<TokenDelivery>(
              initialValue: quickDelivery, isExpanded: true,
              decoration: const InputDecoration(label: LText('Send authentication as')),
              items: TokenDelivery.values.map((value) => DropdownMenuItem(value: value, child: LText(tokenDeliveryLabel(value)))).toList(),
              onChanged: busy ? null : (value) => setState(() {
                if (value != null) quickDelivery = value;
                authorized = false; error = null;
                rememberQuickSettings();
              }),
            ),
            if (quickDelivery == TokenDelivery.apiKey || quickDelivery == TokenDelivery.customHeader)
              TextField(controller: quickHeader, enabled: !busy, autocorrect: false,
                decoration: const InputDecoration(label: LText('Credential header name')),
                onChanged: (_) {
                  setState(() { authorized = false; error = null; });
                  rememberQuickSettings();
                }),
            TextField(
              controller: quickToken, enabled: !busy, obscureText: true,
              autocorrect: false, enableSuggestions: false,
              keyboardType: TextInputType.visiblePassword,
              textDirection: TextDirection.ltr,
              decoration: InputDecoration(prefixIcon: const Icon(Icons.key_outlined),
                label: LText(quickDelivery == TokenDelivery.bearer ? 'Bearer token' : 'Token / cookie / key')),
              onChanged: (_) => setState(() { authorized = false; error = null; }),
            ),
            const Padding(padding: EdgeInsets.only(top: 6), child: LText('Enter the credential. It is cleared when the scan starts.')),
            TextButton.icon(
              onPressed: target.scheme == 'https' && quickToken.text.trim().isNotEmpty &&
                  !loadingAuth && !busy ? saveQuickCredential : null,
              icon: const Icon(Icons.save_outlined),
              label: const LText('Save credential securely for this project'),
            ),
          ],
          CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            title: LText(quickLoginEnabled && !quickTokenEnabled
                ? 'I am authorized to access the sign-in site and assess the selected target.'
                : 'I own this target or have permission to assess it.'),
            value: authorized,
            onChanged: busy ? null : (value) => setState(() => authorized = value ?? false),
          ),
          FilledButton.icon(
            onPressed: authorized && !busy && !loadingQuickSettings && !loadingPolicy && !loadingHistory && policyError == null && policy.permits(target) &&
                (!quickLoginEnabled || (quickAuthTransportAllowed && (quickSaved ? auth != null && !loadingAuth : quickTokenEnabled
                    ? quickToken.text.trim().isNotEmpty : quickApiEnabled || quickLoginError == null))) ? quickScan : null,
            icon: Icon(quickLoginEnabled && !quickTokenEnabled ? Icons.login : Icons.play_arrow),
            label: LText(quickSaved ? 'Start automatic scan' : quickApiEnabled ? 'Sign in to API and scan' : quickLoginEnabled && !quickTokenEnabled ? 'Open sign-in and scan' : 'Start automatic scan'),
          ),
          if (error != null) Padding(
            padding: const EdgeInsets.only(top: 8),
            child: LText(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
          ),
          ExpansionTile(
            title: const LText('Default settings'),
            childrenPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            expandedCrossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('${tr(context, 'Maximum pages')}: ${uiNumber(context, policy.quickDefaults.maxPages)}'),
              Text('${tr(context, 'Delay between requests (ms)')}: ${uiNumber(context, policy.quickDefaults.delayMs)}'),
              const LText('Read-only, same origin, with optional browser session or token. No automatic redirects or exploit payloads.'),
            ],
          ),
          if (busy) Padding(padding: const EdgeInsets.symmetric(vertical: 8),
            child: Text('${tr(context, 'Pages checked')}: ${uiNumber(context, visited)} / ${uiNumber(context, policy.quickDefaults.maxPages)}')),
        ],
        if (advanced) ...[
        Text(widget.project.startUrl.toString(), style: Theme.of(context).textTheme.titleMedium),
        const LText('Technology fingerprint · Scoped request · No redirects'),
        if (authLoadError != null) LText(authLoadError!),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => RepresentationMatrixScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.table_chart_outlined), label: const LText('Representation test matrix')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ConfigurationReviewScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.fact_check), label: const LText('Configuration review suite')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ScheduledCheckScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.timer_outlined), label: const LText('Android scheduled HEAD check')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () async { await Navigator.of(context).push(MaterialPageRoute(builder: (_) => AssessmentQueueScreen(project: widget.project, policy: policy))); if (mounted) await loadHistory(); }, icon: const Icon(Icons.schedule), label: const LText('Foreground assessment queue')),
        OutlinedButton.icon(onPressed: busy ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => CustomRulesScreen(projectId: widget.project.id))), icon: const Icon(Icons.rule), label: const LText('Custom scan rules')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy ? null : editPolicy, icon: const Icon(Icons.tune), label: Text('Scan limits: ${policy.maxPages} pages / ${policy.delayMs} ms')),
        if (policyError != null) LText(policyError!),
        if (!policy.permits(target)) const LText('The selected URL is excluded from scanning.'),
        OutlinedButton.icon(onPressed: busy || loadingAuth || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => AccessCheckScreen(project: widget.project, target: target, profiles: profiles, policy: policy))), icon: const Icon(Icons.people_outline), label: const LText('Compare test account access')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null || target.scheme != 'https' || !policy.permits(target) ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => BrowserTrafficScreen(project: widget.project, target: target, policy: policy))), icon: const Icon(Icons.monitor_heart_outlined), label: const LText('Browser traffic observer')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => TrafficLoggerScreen(project: widget.project, policy: policy, auth: auth))), icon: const Icon(Icons.receipt_long), label: const LText('Traffic logger')),
        OutlinedButton.icon(onPressed: busy || loadingAuth || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ManualRequestScreen(project: widget.project, target: target, auth: auth, policy: policy))), icon: const Icon(Icons.http), label: const LText('Request inspector')),
        OutlinedButton.icon(onPressed: busy ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => const InventoryScreen())), icon: const Icon(Icons.description_outlined), label: const LText('Import Swagger / OpenAPI')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ReviewOrganizerScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.note_alt_outlined), label: const LText('Review organizer')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => TunnelScreen(project: widget.project, target: target, policy: policy))), icon: const Icon(Icons.vpn_lock), label: const LText('Local HTTPS tunnel')),
        OutlinedButton.icon(onPressed: busy || loadingAuth || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => LiveWebSocketScreen(project: widget.project, policy: policy, target: target, auth: auth))), icon: const Icon(Icons.cable), label: const LText('Live WebSocket')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => WebSocketInventoryScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.swap_horiz), label: const LText('WebSocket traffic inventory')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => RegressionAuditScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.fact_check_outlined), label: const LText('Security regression audit')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null || target.scheme != 'https' ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => CorsAuditScreen(project: widget.project, target: target, policy: policy))), icon: const Icon(Icons.security), label: const LText('CORS configuration audit')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null || target.scheme != 'https' || !policy.permits(target) ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => TlsAuditScreen(project: widget.project, target: target, policy: policy))), icon: const Icon(Icons.lock_outline), label: const LText('TLS certificate audit')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null || target.scheme != 'https' || !policy.permits(target) ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => SpaInventoryScreen(project: widget.project, target: target, policy: policy))), icon: const Icon(Icons.language), label: const LText('Explore rendered SPA')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null || loadingAuth ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => SavedRoutesScreen(project: widget.project, policy: policy, auth: auth))), icon: const Icon(Icons.list_alt), label: const LText('Saved route inventory')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ExternalFindingsScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.fact_check_outlined), label: const LText('External assessment findings')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => LabCollectorReviewScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.sensors), label: const LText('Remote lab metadata review')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => HarResponseReviewScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.analytics_outlined), label: const LText('Offline HTTPS response review')),
        OutlinedButton.icon(onPressed: busy || loadingPolicy || policyError != null ? null : () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => HarInventoryScreen(project: widget.project, policy: policy))), icon: const Icon(Icons.file_open), label: const LText('Import HAR traffic inventory')),
        DropdownButtonFormField<Uri>(initialValue: target, isExpanded: true, decoration: const InputDecoration(label: LText('Target')), items: widget.project.targets.toSet().map((u) => DropdownMenuItem(value: u, child: Text(u.toString(), overflow: TextOverflow.ellipsis))).toList(), onChanged: busy ? null : (value) => setState(() { target = value!; selectedProfile = ''; authorized = false; result = null; crawlResult = null; })),
        DropdownButtonFormField<String>(
          key: ValueKey('auth.${target.origin}.$selectedProfile'),
          initialValue: selectedProfile,
          decoration: const InputDecoration(label: LText('Test identity')),
          items: [const DropdownMenuItem(value: '', child: LText('No authentication')), ...profiles.where((p) => SecurityProject.sameOrigin(p.target, target)).map((p) => DropdownMenuItem(value: p.name, child: Text(p.name)))],
          onChanged: busy || loadingAuth ? null : (value) => setState(() { selectedProfile = value ?? ''; authorized = false; result = null; crawlResult = null; }),
        ),
        Wrap(spacing: 8, children: [
          OutlinedButton.icon(onPressed: busy || loadingAuth ? null : () => editAuth(add: true), icon: const Icon(Icons.person_add), label: const LText('Add identity')),
          OutlinedButton.icon(onPressed: busy || loadingAuth || target.scheme != 'https' ? null : addOAuth, icon: const Icon(Icons.login), label: const LText('Add OAuth identity')),
          if (auth != null && auth!.oauth == null) OutlinedButton(onPressed: busy || loadingAuth ? null : () => editAuth(), child: const LText('Edit')),
          if (auth?.oauth != null) OutlinedButton(onPressed: busy || loadingAuth || auth!.oauth!.refreshToken.isEmpty ? null : refreshOAuth, child: const LText('Refresh OAuth token')),
          if (auth != null) OutlinedButton(onPressed: busy || loadingAuth || loadingPolicy || policyError != null ? null : () {
            final profile = auth;
            if (profile == null) return;
            Navigator.of(context).push(MaterialPageRoute(builder: (_) => SessionCheckScreen(project: widget.project, target: target, profile: profile, policy: policy)));
          }, child: const LText('Check session')),
          if (auth != null) OutlinedButton(onPressed: busy || loadingAuth ? null : removeAuth, child: const LText('Delete')),
        ]),
        if (auth != null && auth!.validationUrl.isEmpty) const LText('Session not independently verified. Configure a protected validation URL for reliable authenticated scanning.'),
        CheckboxListTile(
          title: const LText('I own this target or have permission to assess it.'),
          value: authorized,
          onChanged: busy ? null : (value) => setState(() => authorized = value ?? false),
        ),
        FilledButton.icon(onPressed: authorized && !busy && !loadingAuth && !loadingHistory && !loadingPolicy && policyError == null && policy.permits(target) ? scan : null, icon: const Icon(Icons.search), label: const LText('Identify technologies')),
        if (checkpointError != null) LText(checkpointError!),
        if (checkpoint != null) ...[
          const LText('Saved crawl checkpoint. Resume with the same target and identity; previously saved findings remain in scan history.'),
          Text(checkpoint!.start.toString()),
          Text('${uiNumber(context, checkpoint!.attempted)} / ${uiNumber(context, checkpoint!.seen.length)}'),
          OutlinedButton(onPressed: authorized && !busy && !loadingAuth && !loadingPolicy && !loadingCheckpoint &&
            checkpointError == null && policyError == null && checkpoint!.start == target && checkpoint!.identity == (auth?.name ?? '')
            ? () => crawl(resume: true) : null, child: const LText('Resume saved crawl')),
        ],
        if (checkpoint != null || checkpointError != null)
          OutlinedButton(onPressed: busy || loadingCheckpoint ? null : discardCheckpoint, child: const LText('Discard saved crawl')),
        FilledButton.tonalIcon(onPressed: authorized && !busy && !loadingAuth && !loadingPolicy && !loadingCheckpoint && checkpoint == null &&
          checkpointError == null && policyError == null && policy.permits(target) ? crawl : null, icon: const Icon(Icons.account_tree_outlined), label: Text('${tr(context, 'Assess linked pages')} (${uiNumber(context, policy.maxPages)})')),
        ],
        if (busy) const LinearProgressIndicator(),
        if (!advanced && quickReport != null && crawlResult != null) ...[
          Card(child: Padding(padding: const EdgeInsets.all(16), child: Column(
            crossAxisAlignment: CrossAxisAlignment.start, children: [
              LText(quickStatus(crawlResult!.stopReason), style: Theme.of(context).textTheme.titleLarge),
              const SizedBox(height: 8),
              Text('${tr(context, 'Pages checked')}: ${uiNumber(context, quickReport!.pages.length)}'),
              Text('${tr(context, 'Failed requests')}: ${uiNumber(context, quickReport!.failedCount)}'),
              Text('${tr(context, 'Security observations')}: ${uiNumber(context, quickReport!.observationCount)}'),
              const SizedBox(height: 8),
              Wrap(spacing: 8, runSpacing: 4, children: [
                for (final severity in Severity.values.reversed)
                  Chip(
                    backgroundColor: severityColor(context, severity.name).withValues(alpha: .12),
                    label: Text('${tr(context, severity.name)}: ${uiNumber(context, crawlResult!.pages.expand((page) => page.findings).where((finding) => finding.severity == severity).length)}')),
              ]),
              Text('${tr(context, 'Accessible files')}: ${uiNumber(context, quickReport!.files.where((f) => f['outcome'] == 'File accessible').length)}'),
              if (crawlResult!.pages.any((page) => page.statusCode == 401 || page.statusCode == 403))
                const LText('Access was not validated. Check authentication and permissions.'),
              const LText('Observations are not proof of vulnerabilities. A clean result is not a security guarantee.'),
              const SizedBox(height: 8),
              FilledButton.tonalIcon(
                onPressed: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ReportScreen(record: quickReport!))),
                icon: const Icon(Icons.description_outlined), label: const LText('View full report'),
              ),
            ]))),
        ],
        if (!advanced && quickReport != null && crawlResult != null) ...[
          LText('Security observations', style: Theme.of(context).textTheme.titleLarge),
          for (final page in crawlResult!.pages)
            for (final finding in page.findings)
              FindingTile(id: finding.id, title: finding.title, severity: finding.severity.name, evidence: finding.evidence, remediation: finding.remediation, url: page.url.toString()),
          LText('Pages and technology observations', style: Theme.of(context).textTheme.titleLarge),
          for (final page in crawlResult!.pages)
            Card(child: ExpansionTile(title: Text(page.url.toString()), subtitle: Text('HTTP ${page.statusCode}'),
              children: [
                for (final tech in page.technologies)
                  TechnologyTile(name: tech.name, layer: tech.layer.name, confidence: tech.confidence.name, evidence: tech.evidence, version: tech.observedVersion),
                if (page.technologies.isEmpty) const ListTile(title: LText('Unknown — insufficient evidence')),
              ])),
        ],
        if (advanced && crawlResult != null) ...[
          Text('Pages: ${crawlResult!.pages.length} · Failed: ${crawlResult!.failedCount} · ${crawlResult!.stopReason}'),
          for (final page in crawlResult!.pages) ExpansionTile(title: Text(page.url.toString()), subtitle: Text('HTTP ${page.statusCode} · ${page.findings.length} observations'), children: [
            for (final finding in page.findings) FindingTile(id: finding.id, title: finding.title, severity: finding.severity.name, evidence: finding.evidence, remediation: finding.remediation),
          ]),
        ],
        if (advanced && error != null) LText(error!),
        const Divider(),
        const LText('Scan history'),
        if (loadingHistory) const LinearProgressIndicator(),
        if (historyError != null) LText(historyError!),
        for (final (index, item) in history.indexed) ListTile(
          onTap: () => Navigator.of(context).push(MaterialPageRoute(builder: (_) => ReportScreen(record: item, baselines: history.skip(index + 1).toList()))),
          title: Text(item.finishedAt.toLocal().toString().split('.').first),
          subtitle: Text('${item.pages.length} pages · ${item.observationCount} observations'),
          trailing: IconButton(tooltip: tr(context, 'Copy sanitized JSON report'), icon: const Icon(Icons.copy), onPressed: () async {
            await Clipboard.setData(ClipboardData(text: item.exportJson()));
            if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: LText('Report copied.')));
          }),
        ),
        if (advanced && data != null) ...[
          const SizedBox(height: 16),
          Text('HTTP ${data.statusCode}'),
          if (data.statusCode == 401 || data.statusCode == 403) const LText('Access was not validated. Check authentication and permissions.'),
          if (data.redirectNotFollowed) const LText('Redirect not followed. Review the destination before adding it to scope.'),
          if (data.bodyTruncated) const LText('Response body was truncated; coverage is limited.'),
          const Divider(),
          Text('Security observations (${data.findings.length})'),
          for (final finding in data.findings) FindingTile(id: finding.id, title: finding.title, severity: finding.severity.name, evidence: finding.evidence, remediation: finding.remediation),
          for (final layer in TechnologyLayer.values) ...[
            const Divider(),
            Text(layer.name.toUpperCase(), style: Theme.of(context).textTheme.titleSmall),
            if (!data.technologies.any((f) => f.layer == layer)) const LText('Unknown — insufficient evidence'),
            for (final finding in data.technologies.where((f) => f.layer == layer))
              TechnologyTile(name: finding.name, layer: finding.layer.name, confidence: finding.confidence.name, evidence: finding.evidence, version: finding.observedVersion),
          ],
        ],
      ]),
    );
  }
}
