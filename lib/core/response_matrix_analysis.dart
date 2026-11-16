import 'dart:convert';

/// Sanitized response metrics only: no URLs, content, headers, credentials,
/// request templates or transport are accepted or returned by this module.
class ResponseMetrics {
  final int status, bodyBytes, elapsedMs;
  final bool truncated;
  final int? expectedStatus;
  ResponseMetrics({required this.status, required this.bodyBytes, required this.elapsedMs,
      required this.truncated, this.expectedStatus}) {
    if (status < 100 || status > 599 || bodyBytes < 0 || bodyBytes > 1073741824 ||
        elapsedMs < 0 || elapsedMs > 86400000 ||
        (expectedStatus != null && (expectedStatus! < 100 || expectedStatus! > 599))) {
      throw const FormatException('Invalid response metrics.');
    }
  }
  bool? get matchesExpectation => expectedStatus == null ? null : status == expectedStatus;
}

class ResponseDifference {
  final int index;
  final ResponseMetrics sample, baseline;
  final int sizeTolerance, timeToleranceMs;
  const ResponseDifference(this.index,this.sample,this.baseline,this.sizeTolerance,this.timeToleranceMs);
  bool get statusChanged => sample.status != baseline.status;
  int? get sizeDelta => sample.truncated || baseline.truncated ? null : sample.bodyBytes - baseline.bodyBytes;
  int get timeDeltaMs => sample.elapsedMs - baseline.elapsedMs;
  bool get sizeOutsideTolerance => sizeDelta != null && sizeDelta!.abs() > sizeTolerance;
  bool get timeOutsideTolerance => timeDeltaMs.abs() > timeToleranceMs;
  bool get differs => statusChanged || sizeOutsideTolerance || timeOutsideTolerance;
}

class ResponseMatrixAnalysis {
  static const maxCases = 100;

  /// Import sanitized metrics explicitly supplied by the user. Deliberately
  /// strict schema: unknown fields and raw response data cause rejection.
  static List<ResponseMetrics> parse(String source) {
    if (source.length > 65536) throw const FormatException('Metrics exceed limit.');
    final data=jsonDecode(source);
    if (data is! Map || data.length != 2 || data['schema'] != 'odin.security.response-metrics.v1' || data['cases'] is! List) {
      throw const FormatException('Invalid metrics document.');
    }
    final rows=data['cases'] as List;
    if (rows.isEmpty || rows.length > maxCases) throw const FormatException('Invalid case count.');
    final result=<ResponseMetrics>[];
    for (final row in rows) {
      if (row is! Map || row.length < 4 || row.length > 5 ||
          !row.keys.every((k)=>['status','bodyBytes','elapsedMs','truncated','expectedStatus'].contains(k)) ||
          row['status'] is! int || row['bodyBytes'] is! int || row['elapsedMs'] is! int ||
          row['truncated'] is! bool ||
          (row.containsKey('expectedStatus') && row['expectedStatus'] is! int)) {
        throw const FormatException('Invalid case metrics.');
      }
      result.add(ResponseMetrics(status:row['status'] as int,bodyBytes:row['bodyBytes'] as int,
        elapsedMs:row['elapsedMs'] as int,truncated:row['truncated'] as bool,
        expectedStatus:row['expectedStatus'] as int?));
    }
    return List.unmodifiable(result);
  }

  static List<ResponseDifference> compare(List<ResponseMetrics> samples, int baselineIndex,
      {int sizeTolerance=1024,int timeToleranceMs=250}) {
    if (samples.isEmpty || samples.length > maxCases || baselineIndex < 0 || baselineIndex >= samples.length ||
        sizeTolerance < 0 || sizeTolerance > 1073741824 || timeToleranceMs < 0 || timeToleranceMs > 86400000) {
      throw const FormatException('Invalid comparison settings.');
    }
    final baseline=samples[baselineIndex];
    return List.unmodifiable([
      for(var index=0;index<samples.length;index++)
        ResponseDifference(index,samples[index],baseline,sizeTolerance,timeToleranceMs),
    ]);
  }
}
