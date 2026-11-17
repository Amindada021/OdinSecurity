import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/scan_policy.dart';

void main() {
  test('quick defaults are bounded and never relax stored policy', () {
    final defaultPolicy = ScanPolicy().quickDefaults;
    expect(defaultPolicy.maxPages, 12);
    expect(defaultPolicy.delayMs, 1000);
    final strict = ScanPolicy(maxPages: 3, delayMs: 2500, excludedPaths: ['/private']).quickDefaults;
    expect(strict.maxPages, 3);
    expect(strict.delayMs, 2500);
    expect(strict.permits(Uri.parse('https://example.test/private/item')), isFalse);
    final relaxed = ScanPolicy(maxPages: 30, delayMs: 500).quickDefaults;
    expect(relaxed.maxPages, 12);
    expect(relaxed.delayMs, 1000);
  });
}
