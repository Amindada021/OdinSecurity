import 'auth.dart';
import 'manual_request.dart';
import 'project.dart';
import 'scan_policy.dart';

/// Immutable description of a single manually prepared request.
/// No credentials, response data, or network access.
class RequestReview {
  final Uri target;
  final String method;
  final ManualAccept accept;
  final bool authenticated;

  const RequestReview._(this.target, this.method, this.accept, this.authenticated);

  factory RequestReview.prepare(SecurityProject project, String url, String method,
      ManualAccept accept, ScanPolicy policy, {AuthProfile? auth}) {
    final target = Uri.parse(url.trim());
    ManualRequestClient.validate(project, target, method, true, policy: policy);
    if (auth != null && !SecurityProject.sameOrigin(auth.target, target)) {
      throw StateError('Credential origin mismatch.');
    }
    return RequestReview._(target, method, accept, auth != null);
  }

  /// Check again immediately before an explicitly approved send.
  void validate(SecurityProject project, ScanPolicy policy, {required bool approved, AuthProfile? auth}) {
    ManualRequestClient.validate(project, target, method, approved, policy: policy);
    if (authenticated != (auth != null) ||
        (auth != null && !SecurityProject.sameOrigin(auth.target, target))) {
      throw StateError('Credential selection changed.');
    }
  }
}
