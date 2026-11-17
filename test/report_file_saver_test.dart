import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/report_file_saver.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final bytes = Uint8List.fromList([37, 80, 68, 70, 45]);

  setUp(() => debugDefaultTargetPlatformOverride = TargetPlatform.android);
  tearDown(() {
    messenger.setMockMethodCallHandler(ReportFileSaver.channel, null);
    debugDefaultTargetPlatformOverride = null;
  });

  test('passes real bytes to Android report writer and validates count', () async {
    messenger.setMockMethodCallHandler(ReportFileSaver.channel, (call) async {
      expect(call.method, 'save');
      expect(call.arguments['fileName'], 'report.pdf');
      expect(call.arguments['mime'], 'application/pdf');
      expect(call.arguments['bytes'], orderedEquals(bytes));
      return bytes.length;
    });
    expect(await ReportFileSaver.save(fileName: 'report.pdf', extension: 'pdf', bytes: bytes), isTrue);
  });
  test('does not report success for an empty or partial Android write', () async {
    messenger.setMockMethodCallHandler(ReportFileSaver.channel, (_) async => 0);
    await expectLater(ReportFileSaver.save(fileName: 'report.json', extension: 'json', bytes: bytes), throwsStateError);
    await expectLater(ReportFileSaver.save(fileName: 'report.pdf', extension: 'pdf', bytes: Uint8List(0)), throwsFormatException);
  });
  test('cancelled picker is not a successful save', () async {
    messenger.setMockMethodCallHandler(ReportFileSaver.channel, (_) async => null);
    expect(await ReportFileSaver.save(fileName: 'report.html', extension: 'html', bytes: bytes), isFalse);
  });
}
