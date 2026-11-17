import 'dart:async';
import 'package:flutter/material.dart';
import 'localized.dart';
import 'core/crawler.dart';

typedef TerminalLine = ({String tag, String message, String detail});

class ScanTerminal extends StatefulWidget {
  final List<TerminalLine> lines;
  final CancellationFlag control;
  final int pages, requests, maxRequests;
  final VoidCallback onToggle, onStop;
  const ScanTerminal({super.key, required this.lines, required this.control,
    required this.pages, this.requests = 0, this.maxRequests = 100, required this.onToggle, required this.onStop});
  @override
  State<ScanTerminal> createState() => _ScanTerminalState();
}

class _ScanTerminalState extends State<ScanTerminal> {
  final clock = Stopwatch()..start();
  late final Timer timer;
  @override
  void initState() {
    super.initState();
    timer = Timer.periodic(const Duration(seconds: 1), (_) => setState(() {}));
  }
  @override
  void dispose() {
    timer.cancel();
    super.dispose();
  }
  @override
  Widget build(BuildContext context) {
    final flag = widget.control;
    return ColoredBox(color: const Color(0xff08100f), child: SafeArea(child: Padding(
      padding: const EdgeInsets.all(16), child: Column(children: [
        Row(children: [
          const Icon(Icons.terminal, color: Colors.tealAccent),
          const SizedBox(width: 8),
          Expanded(child: LText(flag.cancelled ? 'Stopping after current request' : flag.paused ? 'Paused between requests' : 'Scan running',
            style: const TextStyle(color: Colors.white))),
          Text('${clock.elapsed.inMinutes}:${(clock.elapsed.inSeconds % 60).toString().padLeft(2, '0')}', style: const TextStyle(color: Colors.tealAccent, fontFamily: 'monospace')),
        ]),
        const SizedBox(height: 12),
        LinearProgressIndicator(value: flag.paused || flag.cancelled ? 0 : null, color: Colors.tealAccent),
        Expanded(child: ListView.builder(reverse: true, padding: const EdgeInsets.symmetric(vertical: 12),
          itemCount: widget.lines.length, itemBuilder: (context, i) {
            final line = widget.lines[widget.lines.length - 1 - i];
            final color = switch (line.tag) {
              'WARN' => Colors.amberAccent, 'FOUND' => Colors.orangeAccent,
              'HTTP' => Colors.greenAccent, _ => Colors.tealAccent,
            };
            return Padding(padding: const EdgeInsets.symmetric(vertical: 3),
              child: Text('[${line.tag}] ${tr(context, line.message)} ${line.detail}',
                style: TextStyle(color: color, fontFamily: 'monospace')));
          })),
        Text('${tr(context, 'Requests used')}: ${uiNumber(context, widget.requests)} / ${widget.maxRequests == 0 ? tr(context, 'Unlimited') : uiNumber(context, widget.maxRequests)}', style: const TextStyle(color: Colors.tealAccent)),
        Text('${tr(context, 'Pages checked')} · ${uiNumber(context, widget.pages)}', style: const TextStyle(color: Colors.white)),
        Wrap(spacing: 12, children: [
          FilledButton.tonal(onPressed: flag.cancelled ? null : widget.onToggle, child: LText(flag.paused ? 'Resume scan' : 'Pause scan')),
          FilledButton(onPressed: flag.cancelled ? null : widget.onStop, child: const LText('Stop')),
        ]),
      ]))));
  }
}
