import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/local_lab_receiver.dart';

void main() {
  test('loopback receiver accepts only exact local token route and bounded metadata', () async {
    final receiver = LocalLabReceiver();
    final client = HttpClient();
    try {
      await expectLater(receiver.start(approved:false), throwsStateError);
      await receiver.start(approved:true);
      final endpoint = receiver.endpoint!;
      expect(endpoint.host, '127.0.0.1');
      final wrong = await (await client.getUrl(endpoint.resolve('/wrong'))).close();
      expect(wrong.statusCode, 404);
      await wrong.drain<void>();
      final right = await (await client.getUrl(endpoint)).close();
      expect(right.statusCode, 204);
      await right.drain<void>();
      expect(receiver.events, hasLength(1));
      expect(receiver.events.single.method, 'GET');
      final query = await (await client.getUrl(endpoint.replace(query:'ignored=1'))).close();
      expect(query.statusCode, 404);
      await query.drain<void>();
      expect(receiver.events, hasLength(1));
    } finally { client.close(force:true); await receiver.dispose(); }
  });
}
