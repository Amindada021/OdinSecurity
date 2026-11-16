import 'package:flutter/material.dart';
import 'core/data_analysis.dart';
import 'localized.dart';

class ComparerScreen extends StatefulWidget {
  const ComparerScreen({super.key});
  @override
  State<ComparerScreen> createState() => _ComparerScreenState();
}

class _ComparerScreenState extends State<ComparerScreen> {
  final left = TextEditingController(), right = TextEditingController();
  List<DiffLine>? result;
  String? error;
  bool changesOnly = false;

  @override
  void dispose() { left.dispose(); right.dispose(); super.dispose(); }

  void compare() {
    try {
      final found = TextDiff.compare(left.text, right.text);
      setState(() { result = found; error = null; });
    } catch (_) {
      setState(() { result = null; error = 'Comparison input exceeds limits.'; });
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const LText('Message comparer')),
    body: ListView(padding: const EdgeInsets.all(16), children: [
      const LText('Compare two local text or HTTP message samples. Maximum 300 lines and 65536 characters each. Nothing is sent or saved. Use sanitized data.'),
      TextField(controller: left, maxLines: 5, autocorrect: false, enableSuggestions: false,
        decoration: const InputDecoration(label: LText('Original message'))),
      TextField(controller: right, maxLines: 5, autocorrect: false, enableSuggestions: false,
        decoration: const InputDecoration(label: LText('Updated message'))),
      Wrap(spacing: 8, children: [
        FilledButton(onPressed: compare, child: const LText('Compare')),
        OutlinedButton(onPressed: () { left.clear(); right.clear(); setState(() { result = null; error = null; }); }, child: const LText('Clear')),
      ]),
      if (error != null) LText(error!),
      if (result != null) ...[
        CheckboxListTile(value: changesOnly, title: const LText('Show changes only'), onChanged: (v) => setState(() => changesOnly = v ?? false)),
        for (final line in result!.where((line) => !changesOnly || line.kind != DiffKind.same))
          Container(padding: const EdgeInsets.symmetric(vertical: 3, horizontal: 6),
            color: switch (line.kind) {
              DiffKind.added => Colors.green.withValues(alpha: 0.16),
              DiffKind.removed => Colors.red.withValues(alpha: 0.16),
              DiffKind.same => Colors.transparent,
            },
            child: SelectableText('${switch (line.kind) { DiffKind.same => " ", DiffKind.added => "+", DiffKind.removed => "-" }} ${line.text}',
              textDirection: TextDirection.ltr, style: const TextStyle(fontFamily: 'monospace'))),
      ],
    ]),
  );
}

class TokenSamplesScreen extends StatefulWidget {
  const TokenSamplesScreen({super.key});
  @override
  State<TokenSamplesScreen> createState() => _TokenSamplesScreenState();
}

class _TokenSamplesScreenState extends State<TokenSamplesScreen> {
  final source = TextEditingController();
  SampleReport? result;
  String? error;
  @override
  void dispose() { source.dispose(); super.dispose(); }

  void analyze() {
    try {
      final found = TokenSampleAnalyzer.analyze(source.text);
      source.clear();
      setState(() { result = found; error = null; });
    } catch (_) {
      setState(() { result = null; error = 'Invalid sample input.'; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final data = result;
    return Scaffold(appBar: AppBar(title: const LText('Token sample analysis')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        const LText('Paste synthetic or non-secret test samples, one per line. No live capture or request generation. Input is cleared after analysis.'),
        TextField(controller: source, maxLines: 7, autocorrect: false, enableSuggestions: false,
          decoration: const InputDecoration(label: LText('Token samples'))),
        FilledButton(onPressed: analyze, child: const LText('Analyze samples')),
        if (error != null) LText(error!),
        if (data != null) ...[
          for (final row in <String, String>{
            'Samples': uiNumber(context, data.count), 'Unique samples': uiNumber(context, data.unique),
            'Duplicates': uiNumber(context, data.duplicates), 'Minimum length': uiNumber(context, data.minLength),
            'Maximum length': uiNumber(context, data.maxLength), 'Distinct characters': uiNumber(context, data.distinctCharacters),
            'Observed character entropy': '${data.observedCharacterEntropy.toStringAsFixed(3)} bits',
            'Varying positions': data.varyingPositions.join(', '),
            'Adjacent duplicates': uiNumber(context, data.adjacentDuplicates),
            if (data.adjacentDifferenceRatio != null) 'Adjacent character difference': (data.adjacentDifferenceRatio! * 100).toStringAsFixed(2) + '%',
            if (data.hexOneBitRatio != null) 'Hex one-bit proportion': (data.hexOneBitRatio! * 100).toStringAsFixed(2) + '%',
          }.entries)
            ListTile(title: LText(row.key), subtitle: Text(row.value)),
          ExpansionTile(title: const LText('Per-position entropy'), children: [
            for (final position in data.positions)
              ListTile(dense: true, title: Text('#${position.position} · ${position.distinct}'),
                subtitle: Text('Shannon ${position.shannonEntropy.toStringAsFixed(3)} | Min ${position.empiricalMinEntropy.toStringAsFixed(3)} bits')),
          ]),
          const LText('These are descriptive sample statistics, not proof of cryptographic randomness or token security.'),
        ],
      ]));
  }
}
