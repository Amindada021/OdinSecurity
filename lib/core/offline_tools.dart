import 'dart:convert';

class OfflineTools {
  static String encodeBase64(String text) => base64Encode(utf8.encode(text));
  static String decodeBase64(String text) => utf8.decode(base64Decode(base64.normalize(text.trim())));
  static String encodeUrl(String text) => Uri.encodeComponent(text);
  static String decodeUrl(String text) => Uri.decodeComponent(text);
  static String formatJson(String text) => const JsonEncoder.withIndent('  ').convert(jsonDecode(text));

  /// Decoding is not signature verification. No token leaves the device.
  static String inspectJwt(String token) {
    final parts = token.trim().split('.');
    if (parts.length != 3) throw const FormatException('Expected a three-part signed JWT.');
    final header = jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(parts[0]))));
    final claims = jsonDecode(utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))));
    if (header is! Map || claims is! Map) throw const FormatException('Invalid JWT JSON.');
    return const JsonEncoder.withIndent('  ').convert({'verified': false, 'header': header, 'claims': claims});
  }
}
