import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  test('quick scans honor the saved dynamic request budget and delay', () {
    final defaultPolicy = ScanPolicy().quickDefaults;
    expect(defaultPolicy.maxRequests, 100);
    expect(defaultPolicy.delayMs, 1000);
    final strict = ScanPolicy(maxPages: 3, delayMs: 2500, excludedPaths: ['/private']).quickDefaults;
    expect(strict.maxPages, 3);
    expect(strict.delayMs, 2500);
    expect(strict.permits(Uri.parse('https://example.test/private/item')), isFalse);
    final relaxed = ScanPolicy(maxPages: 30, delayMs: 500).quickDefaults;
    expect(relaxed.maxRequests, 30);
    expect(relaxed.delayMs, 500);
    final unlimited = ScanPolicy(maxRequests: 0).quickDefaults;
    expect(unlimited.exhausted(100000), false);
    expect(ScanPolicy.fromJson(unlimited.toJson()).unlimited, true);
    expect(() => ScanPolicy(maxRequests: -1), throwsFormatException);
  });
}
