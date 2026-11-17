import 'package:flutter/material.dart';
import 'localized.dart';
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
    pages = TextEditingController(text: widget.policy.maxRequests.toString());
    delay = TextEditingController(text: widget.policy.delayMs.toString());
    paths = TextEditingController(text: widget.policy.excludedPaths.join('\n'));
  }
  @override
  void dispose() { pages.dispose(); delay.dispose(); paths.dispose(); super.dispose(); }

  void save() {
    try {
      final policy = ScanPolicy(maxRequests: int.parse(pages.text.trim().replaceAllMapped(RegExp('[۰-۹٠-٩]'), (m) {
          final ch = m[0]!.codeUnitAt(0);
          return (ch >= 0x6f0 ? ch - 0x6f0 : ch - 0x660).toString();
        })), delayMs: int.parse(delay.text),
        excludedPaths: paths.text.split('\n').map((p) => p.trim()).where((p) => p.isNotEmpty).toList());
      Navigator.pop(context, policy);
    } on FormatException catch (e) {
      setState(() => error = e.message);
    }
  }
  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const LText('Scan limits'),
    content: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
      TextField(controller: pages, keyboardType: TextInputType.number, decoration: const InputDecoration(label: LText('Max Requests (0 = unlimited)'))),
      TextField(controller: delay, keyboardType: TextInputType.number, decoration: const InputDecoration(label: LText('Delay between requests (ms)'))),
      TextField(controller: paths, maxLines: 5, decoration: const InputDecoration(label: LText('Excluded path prefixes, one per line'), hintText: '/payments\n/admin/delete')),
      const LText('Crawling only follows eligible same-origin links. It stops on rate limiting or repeated server errors.'),
      if (error != null) LText(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
    ])),
    actions: [
      TextButton(onPressed: () => Navigator.pop(context), child: const LText('Cancel')),
      FilledButton(onPressed: save, child: const LText('Save')),
    ],
  );
}
