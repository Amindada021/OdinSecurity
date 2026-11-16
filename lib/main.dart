import 'package:flutter/material.dart';

import 'core/project.dart';
import 'core/passive_scan.dart';
import 'core/fingerprint.dart';

void main() => runApp(const OdinSecurityApp());

class OdinSecurityApp extends StatelessWidget {
  const OdinSecurityApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Odin Security',
        theme: ThemeData(colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xff22c5a0), brightness: Brightness.dark), useMaterial3: true),
        home: const ProjectScreen(),
      );
}

class ProjectScreen extends StatefulWidget {
  const ProjectScreen({super.key});
  @override
  State<ProjectScreen> createState() => _ProjectScreenState();
}

class _ProjectScreenState extends State<ProjectScreen> {
  final projects = <SecurityProject>[];

  Future<void> addProject() async {
    final project = await showDialog<SecurityProject>(
      context: context,
      builder: (_) => const CreateProjectDialog(),
    );
    if (project != null && mounted) setState(() => projects.add(project));
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Odin Security')),
        floatingActionButton: FloatingActionButton.extended(onPressed: addProject, icon: const Icon(Icons.add), label: const Text('New project')),
        body: projects.isEmpty
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
  String? error;
  @override
  void dispose() {
    name.dispose();
    url.dispose();
    super.dispose();
  }

  void submit() {
    try {
      Navigator.of(context).pop(SecurityProject(name: name.text, url: url.text));
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
  bool busy = false;
  PassiveScanResult? result;
  String? error;

  Future<void> scan() async {
    if (!authorized || busy) return;
    setState(() { busy = true; result = null; error = null; });
    try {
      final data = await PassiveScanner().scan(widget.project, authorized: authorized);
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
        const Text('Technology fingerprint · Single HTTP GET · No redirects'),
        CheckboxListTile(
          title: const Text('I own this target or have permission to assess it.'),
          value: authorized,
          onChanged: busy ? null : (value) => setState(() => authorized = value ?? false),
        ),
        FilledButton.icon(onPressed: authorized && !busy ? scan : null, icon: const Icon(Icons.search), label: const Text('Identify technologies')),
        if (busy) const LinearProgressIndicator(),
        if (error != null) Text(error!),
        if (data != null) ...[
          const SizedBox(height: 16),
          Text('HTTP ${data.statusCode}'),
          if (data.redirectNotFollowed) const Text('Redirect not followed. Review the destination before adding it to scope.'),
          if (data.bodyTruncated) const Text('Response body was truncated; coverage is limited.'),
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
