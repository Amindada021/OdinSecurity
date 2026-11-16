import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/history.dart';

void main() {
  test('advisory handoff includes only deduplicated supported declared versions', () {
    final record = ScanRecord(finishedAt: DateTime.utc(2026), failedCount: 0, cancelled: false, pages: [
      {'technologies': [
        {'name':'Nginx','observedVersion':'1.2.3','evidence':'not exported'},
        {'name':'PHP','observedVersion':'8.2.1'},
        {'name':'Nginx','observedVersion':'1.2.3'},
        {'name':'Unknown'},
        {'name':'Other','observedVersion':'1.2.3-custom'},
      ]},
      {'technologies':[{'name':'Nginx','observedVersion':'1.2.4'}]},
    ]);
    expect(record.declaredInventory(), [
      {'product':'Nginx','version':'1.2.3'},
      {'product':'PHP','version':'8.2.1'},
      {'product':'Nginx','version':'1.2.4'},
    ]);
  });
}
