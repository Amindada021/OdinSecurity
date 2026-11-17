import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:odin_security/core/load_test_engine.dart';
import 'package:odin_security/core/load_test_policy.dart';
import 'package:odin_security/core/project.dart';

void main() {
  final project = SecurityProject(name: 'Lab', url: 'https://staging.example.test/load-test/health');
  final now = DateTime.utc(2026, 11, 18);
  Map<String, dynamic> policy() => {
    'schemaVersion': 1, 'purpose': 'odinsecurity-load-test', 'challenge': 'fixture',
    'origin': project.startUrl.origin, 'environment': 'staging', 'permitId': 'fixture-policy',
    'allowedAddresses': ['127.0.0.1'], 'allowedPaths': ['/load-test/health'],
    'expiresAt': now.add(const Duration(minutes: 15)).toIso8601String(),
    'maxConcurrentUsers': 10, 'maxRps': 20, 'maxDurationSeconds': 120,
    'maxTimeoutSeconds': 10, 'maxTotalRequests': 2400,
    'capacityUsers': 5, 'capacityRps': 10, 'baselineLatencyMs': 100,
    'stopLatencyMs': 2000, 'stopErrorPercent': 20, 'minimumSamples': 20,
  };
  LabPermit parse(Map<String, dynamic> j) => LabPermit.fromVerifiedResponse(j,
    project.startUrl, InternetAddress.loopbackIPv4, 'fixture', now);

  test('red risk does not reject a configuration inside administrator ceilings', () {
    final permit = parse(policy());
    final config = LoadTestConfig(target: project.startUrl, users: 10, rps: 20);
    expect(permit.risk(config), LoadRisk.disruption);
    expect(() => permit.validate(config, project, now), returnsNormally);
    expect(() => permit.validate(LoadTestConfig(target: project.startUrl, users: 11), project, now), throwsFormatException);
  });
  test('production, replayed nonce and unapproved address cannot create authority', () {
    for (final entry in [('environment', 'production'), ('challenge', 'other'),
      ('origin', 'https://other.test'), ('allowedAddresses', ['192.168.1.2'])]) {
      final j = policy()..[entry.$1] = entry.$2;
      expect(() => parse(j), throwsFormatException);
    }
  });
  test('exact paths and finite laboratory settings are mandatory', () {
    final permit = parse(policy());
    expect(() => permit.validate(LoadTestConfig(target: project.startUrl.resolve('/other')), project, now), throwsFormatException);
    expect(() => LoadTestConfig(target: project.startUrl, rps: 0).validate(), throwsFormatException);
    expect(() => LoadTestConfig(target: project.startUrl, users: 51).validate(), throwsFormatException);
    expect(LabPermitVerifier.allowedAddress(InternetAddress('169.254.169.254')), false);
    expect(LabPermitVerifier.allowedAddress(InternetAddress('0.0.0.0')), false);
    expect(LabPermitVerifier.allowedAddress(InternetAddress.loopbackIPv4), true);
  });
}
