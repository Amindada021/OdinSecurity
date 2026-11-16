import 'auth.dart';
import 'manual_request.dart';
import 'project.dart';
import 'scan_policy.dart';

/// Immutable description of a single manually prepared request.
/// Ephemeral user-entered request values; no saved credentials, response data or network access.
class RequestReview {
  final Uri target;
  final String method;
  final ManualAccept accept;
  final bool authenticated, stagingConfirmed;
  final ManualRequestOptions options;

  const RequestReview._(this.target, this.method, this.accept, this.authenticated, this.options, this.stagingConfirmed);

  factory RequestReview.prepare(SecurityProject project, String url, String method,
      ManualAccept accept, ScanPolicy policy, {AuthProfile? auth,
      ManualRequestOptions options = const ManualRequestOptions.empty(), bool stagingConfirmed = false}) {
    final target = Uri.parse(url.trim());
    ManualRequestClient.validate(project, target, method, true, policy: policy, options: options, stagingConfirmed: stagingConfirmed);
    if (auth != null && !SecurityProject.sameOrigin(auth.target, target)) {
      throw StateError('Credential origin mismatch.');
    }
    return RequestReview._(target, method, accept, auth != null, options, stagingConfirmed);
  }

  /// Check again immediately before an explicitly approved send.
  void validate(SecurityProject project, ScanPolicy policy, {required bool approved, AuthProfile? auth}) {
    ManualRequestClient.validate(project, target, method, approved, policy: policy, options: options, stagingConfirmed: stagingConfirmed);
    if (authenticated != (auth != null) ||
        (auth != null && !SecurityProject.sameOrigin(auth.target, target))) {
      throw StateError('Credential selection changed.');
    }
  }
}
