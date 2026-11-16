import 'dart:math';
import 'package:flutter/material.dart';

class OdinLogo extends StatelessWidget {
  final double size;
  const OdinLogo({super.key, this.size = 44});
  @override
  Widget build(BuildContext context) => Semantics(
    label: 'Odin Security',
    child: SizedBox.square(dimension: size, child: CustomPaint(painter: _LogoPainter())),
  );
}

class _LogoPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    canvas.save();
    canvas.scale(size.width / 100, size.height / 100);
    final navy = Paint()..color = const Color(0xff071522);
    final teal = Paint()
      ..color = const Color(0xff0bd4a7)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 5
      ..strokeJoin = StrokeJoin.round;
    canvas.drawRRect(RRect.fromRectAndRadius(const Rect.fromLTWH(0, 0, 100, 100), const Radius.circular(19)), navy);
    final shield = Path()
      ..moveTo(50, 12)..lineTo(82, 26)..lineTo(82, 51)
      ..cubicTo(82, 66, 71, 78, 50, 89)
      ..cubicTo(29, 78, 18, 66, 18, 51)
      ..lineTo(18, 26)..close();
    canvas.drawPath(shield, teal);
    teal.strokeWidth = 6;
    const ring = Rect.fromLTWH(30, 29, 40, 40);
    canvas.drawArc(ring, -pi / 2 + .11, pi - .22, false, teal);
    canvas.drawArc(ring, pi / 2 + .11, pi - .22, false, teal);
    teal.strokeWidth = 2.8;
    canvas.drawCircle(const Offset(50, 45), 5, teal);
    canvas.drawLine(const Offset(50, 50), const Offset(50, 57), teal);
    canvas.drawCircle(const Offset(50, 60), 3, teal);
    canvas.restore();
  }
  @override
  bool shouldRepaint(covariant _LogoPainter oldDelegate) => false;
}
