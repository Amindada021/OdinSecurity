import 'package:flutter/material.dart';
import 'core/scan_policy.dart';

class ScanPolicyDialog extends StatefulWidget {
  final ScanPolicy policy;
  const ScanPolicyDialog({super.key, required this.policy});
  @override
  State<ScanPolicyDialog> createState() => _ScanPolicyDialogState();
}
class _ScanPolicyDialogState extends State<ScanPolicyDialog> {
  late final TextEditingController pages, delay, paths;
  String? error;
  @override
  void initState() {
    super.initState();
    pages = TextEditingController(text: widget.policy.maxPages.toString());
    delay = TextEditingController(text: widget.policy.delayMs.toString());
    paths = TextEditingController(text: widget.policy.excludedPaths.join('\n'));
  }
  @override
  void dispose() { pages.dispose(); delay.dispose(); paths.dispose(); super.dispose(); }

  void save() {
    try {
      final policy = ScanPolicy(maxPages: int.parse(pages.text), delayMs: int.parse(delay.text),
        excludedPaths: paths.text.split('\n').map((p) => p.trim()).where((p) => p.isNotEmpty).toList());
      Navigator.pop(context, policy);
    } on FormatException catch (e) {
      setState(() => error = e.message);
    }
  }
  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('Scan limits'),
    content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
      TextField(controller: pages, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Maximum pages (1–30)')),
      TextField(controller: delay, keyboardType: TextInputType.number, decoration: const InputDecoration(labelText: 'Delay between requests (ms)')),
      TextField(controller: paths, maxLines: 5, decoration: const InputDecoration(labelText: 'Excluded path prefixes, one per line', hintText: '/payments\n/admin/delete')),
      const Text('Crawling only follows eligible same-origin links. It stops on rate limiting or repeated server errors.'),
      if (error != null) Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
    ])),
    actions: [
      TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
      FilledButton(onPressed: save, child: const Text('Save')),
    ],
  );
}
