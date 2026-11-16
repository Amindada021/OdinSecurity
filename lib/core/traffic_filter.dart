import 'traffic_journal.dart';

enum TrafficSort { newest, slowest, largest }

class TrafficFilter {
  final String search, source, method;
  final int? statusClass;
  final int minElapsedMs;
  final bool errorsOnly, truncatedOnly, queryOmittedOnly;
  final TrafficSort sort;
  const TrafficFilter({this.search = '', this.source = 'all', this.method = 'all',
    this.statusClass, this.minElapsedMs = 0, this.errorsOnly = false,
    this.truncatedOnly = false, this.queryOmittedOnly = false, this.sort = TrafficSort.newest});

  List<TrafficEntry> apply(Iterable<TrafficEntry> entries) {
    final needle = search.trim().toLowerCase();
    final result = entries.where((entry) {
      if (source != 'all' && entry.source != source) return false;
      if (method != 'all' && entry.method != method) return false;
      final status = entry.status;
      if (errorsOnly && status != null && status < 400) return false;
      if (statusClass != null && (status == null || status ~/ 100 != statusClass)) return false;
      if (entry.elapsedMs < minElapsedMs || truncatedOnly && !entry.truncated ||
          queryOmittedOnly && !entry.hadQuery) return false;
      return needle.isEmpty || (entry.method + ' ' + entry.route.toString() + ' ' + (status?.toString() ?? '')).toLowerCase().contains(needle);
    }).toList();
    result.sort((a, b) {
      final comparison = switch (sort) {
        TrafficSort.newest => 0,
        TrafficSort.slowest => b.elapsedMs.compareTo(a.elapsedMs),
        TrafficSort.largest => (b.capturedBytes ?? -1).compareTo(a.capturedBytes ?? -1),
      };
      return comparison != 0 ? comparison : b.at.compareTo(a.at);
    });
    return List.unmodifiable(result);
  }
}
