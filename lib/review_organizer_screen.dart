import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/project.dart';
import 'core/project_storage.dart';
import 'core/review_organizer.dart';
import 'core/scan_policy.dart';
import 'localized.dart';

class ReviewOrganizerScreen extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  const ReviewOrganizerScreen({super.key, required this.project, required this.policy});
  @override
  State<ReviewOrganizerScreen> createState() => _ReviewOrganizerScreenState();
}

class _ReviewOrganizerScreenState extends State<ReviewOrganizerScreen> {
  List<ReviewItem> items = [];
  bool busy = true, failed = false;
  ReviewStatus? filter;
  ReviewOrganizer? repository;

  @override
  void initState() { super.initState(); load(); }

  Future<void> load() async {
    try {
      final repo = ReviewOrganizer(PreferencesStorage(await SharedPreferences.getInstance()));
      final found = await repo.load(widget.project, widget.policy);
      if (mounted) setState(() { repository = repo; items = found; failed = false; });
    } catch (_) {
      if (mounted) setState(() => failed = true);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> persist(List<ReviewItem> values) async {
    final repo = repository;
    if (repo == null || busy) return;
    setState(() { busy = true; failed = false; });
    try {
      await repo.save(widget.project, widget.policy, values);
      if (mounted) setState(() => items = values);
    } catch (_) {
      if (mounted) setState(() => failed = true);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> edit(int? index) async {
    final old = index == null ? null : items[index];
    final item = await showDialog<ReviewItem>(context: context, builder: (_) => _ReviewEditor(
      project: widget.project, policy: widget.policy, item: old));
    if (item == null || !mounted) return;
    final next = [...items];
    if (index == null) { next.insert(0, item); } else { next[index] = item; }
    await persist(next);
  }

  Future<void> remove(int index) async {
    final yes = await showDialog<bool>(context: context, builder: (context) => AlertDialog(
      title: const LText('Delete review note?'),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context, false), child: const LText('Cancel')),
        FilledButton(onPressed: () => Navigator.pop(context, true), child: const LText('Delete')),
      ],
    ));
    if (yes == true && mounted) await persist([...items]..removeAt(index));
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Review organizer')),
    floatingActionButton: FloatingActionButton(onPressed: busy || repository == null || items.length >= ReviewOrganizer.limit ? null : () => edit(null),
      child: const Icon(Icons.add)),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Save your own sanitized review notes for this project. Do not include passwords, tokens, or customer data.'),
      Wrap(spacing: 8, children: [
        ChoiceChip(label: const LText('All'), selected: filter == null, onSelected: (_) => setState(() => filter = null)),
        for (final status in ReviewStatus.values) ChoiceChip(label: LText(status.name), selected: filter == status, onSelected: (_) => setState(() => filter = status)),
      ]),
      if (busy) const LinearProgressIndicator(),
      if (failed) const LText('Could not load or save review notes.'),
      for (var i = 0; i < items.length; i++)
        if (filter == null || items[i].status == filter)
          Card(child: ListTile(title: Text(items[i].title), subtitle: Text('${items[i].route}\n${tr(context, items[i].status.name)}'),
            onTap: busy ? null : () => edit(i), trailing: IconButton(icon: const Icon(Icons.delete_outline), onPressed: busy ? null : () => remove(i)))),
    ]),
  );
}

class _ReviewEditor extends StatefulWidget {
  final SecurityProject project;
  final ScanPolicy policy;
  final ReviewItem? item;
  const _ReviewEditor({required this.project, required this.policy, this.item});
  @override
  State<_ReviewEditor> createState() => _ReviewEditorState();
}
class _ReviewEditorState extends State<_ReviewEditor> {
  late final TextEditingController route, title, note;
  late ReviewStatus status;
  bool invalid = false;
  @override
  void initState() {
    super.initState();
    route = TextEditingController(text: widget.item?.route.toString() ?? widget.project.startUrl.toString());
    title = TextEditingController(text: widget.item?.title);
    note = TextEditingController(text: widget.item?.note);
    status = widget.item?.status ?? ReviewStatus.open;
  }
  @override
  void dispose() { route.dispose(); title.dispose(); note.dispose(); super.dispose(); }

  void save() {
    try {
      final result = ReviewOrganizer.prepare(widget.project, widget.policy, route.text, title.text, note.text, status);
      Navigator.pop(context, result);
    } catch (_) {
      setState(() => invalid = true);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(title: const LText('Review note'),
    content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
      TextField(controller: route, decoration: const InputDecoration(label: LText('Request URL'))),
      TextField(controller: title, maxLength: 120, decoration: const InputDecoration(label: LText('Review title'))),
      TextField(controller: note, maxLength: 2000, maxLines: 4, decoration: const InputDecoration(label: LText('Review notes'))),
      DropdownButtonFormField<ReviewStatus>(initialValue: status, items: ReviewStatus.values.map((s) => DropdownMenuItem(value: s, child: LText(s.name))).toList(),
        onChanged: (value) => setState(() => status = value ?? ReviewStatus.open)),
      if (invalid) const LText('Invalid review note or out-of-scope route.'),
    ])),
    actions: [
      TextButton(onPressed: () => Navigator.pop(context), child: const LText('Cancel')),
      FilledButton(onPressed: save, child: const LText('Save')),
    ],
  );
}
