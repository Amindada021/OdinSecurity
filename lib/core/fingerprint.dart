enum TechnologyLayer { cms, frontend, backend, server, api }
enum Confidence { low, medium, high }

class HttpObservation {
  final Map<String, List<String>> headers;
  final String body;
  HttpObservation({required Map<String, List<String>> headers, required this.body})
      : headers = {
          for (final entry in headers.entries)
            entry.key.toLowerCase(): entry.value,
        };
  String header(String name) => headers[name.toLowerCase()]?.join('; ') ?? '';
}

class TechnologyFinding {
  final String name;
  final TechnologyLayer layer;
  final Confidence confidence;
  final String evidence;
  const TechnologyFinding(this.name, this.layer, this.confidence, this.evidence);
}

class TechnologyDetector {
  List<TechnologyFinding> detect(HttpObservation observation) {
    final body = observation.body.toLowerCase();
    final server = observation.header('server').toLowerCase();
    final powered = observation.header('x-powered-by').toLowerCase();
    final cookies = observation.header('set-cookie').toLowerCase();
    final generator = RegExp(r'<meta[^>]+name\s*=\s*["\x27]generator["\x27][^>]*>').firstMatch(body)?.group(0) ?? '';
    final results = <TechnologyFinding>[];

    void add(String name, TechnologyLayer layer, Confidence confidence, String evidence) {
      final index = results.indexWhere((item) => item.name == name && item.layer == layer);
      if (index < 0) {
        results.add(TechnologyFinding(name, layer, confidence, evidence));
      } else if (results[index].confidence.index < confidence.index) {
        results[index] = TechnologyFinding(name, layer, confidence, evidence);
      }
    }

    bool anyBody(List<String> values) => values.any(body.contains);

    // Independent observations: a reverse proxy is not an application runtime.
    for (final entry in {
      'nginx': 'Nginx', 'apache': 'Apache', 'microsoft-iis': 'IIS',
      'cloudflare': 'Cloudflare', 'caddy': 'Caddy', 'kestrel': 'Kestrel',
      'gunicorn': 'Gunicorn', 'uvicorn': 'Uvicorn',
      'openresty': 'OpenResty', 'litespeed': 'LiteSpeed', 'tomcat': 'Tomcat',
      'jetty': 'Jetty', 'vercel': 'Vercel', 'traefik': 'Traefik',
    }.entries) {
      if (server.contains(entry.key)) {
        add(entry.value, TechnologyLayer.server, Confidence.medium, 'Server header');
      }
    }

    if (generator.contains('wordpress')) {
      add('WordPress', TechnologyLayer.cms, Confidence.high, 'Generator meta tag');
    } else if (anyBody(['/wp-content/', '/wp-includes/'])) {
      add('WordPress', TechnologyLayer.cms, Confidence.medium, 'WordPress asset paths');
    }
    if (generator.contains('drupal') || observation.header('x-generator').toLowerCase().contains('drupal')) {
      add('Drupal', TechnologyLayer.cms, Confidence.high, 'Generator metadata');
    } else if (body.contains('drupalsettings')) {
      add('Drupal', TechnologyLayer.cms, Confidence.medium, 'Drupal frontend settings');
    }
    if (generator.contains('woocommerce') || anyBody(['/wp-content/plugins/woocommerce/', 'woocommerce-no-js'])) {
      add('WooCommerce', TechnologyLayer.cms, Confidence.medium, 'WooCommerce asset or generator marker');
    }
    if (generator.contains('shopify') || anyBody(['cdn.shopify.com/', 'shopify-section'])) {
      add('Shopify', TechnologyLayer.cms, Confidence.medium, 'Shopify page or asset marker');
    }
    if (generator.contains('ghost')) {
      add('Ghost', TechnologyLayer.cms, Confidence.high, 'Generator meta tag');
    }
    if (generator.contains('joomla')) {
      add('Joomla', TechnologyLayer.cms, Confidence.high, 'Generator meta tag');
    }
    if (powered.contains('php')) {
      add('PHP', TechnologyLayer.backend, Confidence.medium, 'X-Powered-By header');
    } else if (cookies.contains('phpsessid=')) {
      add('PHP', TechnologyLayer.backend, Confidence.medium, 'PHP session cookie name');
    }
    if (cookies.contains('laravel_session=') || powered.contains('laravel')) {
      add('Laravel', TechnologyLayer.backend, Confidence.medium, 'Laravel-specific cookie or header');
    }
    if (observation.header('x-debug-token').isNotEmpty && observation.header('x-debug-token-link').isNotEmpty) {
      add('Symfony', TechnologyLayer.backend, Confidence.medium, 'Framework debugger headers');
    }
    if (server.contains('kestrel') || cookies.contains('.aspnetcore.')) {
      add('ASP.NET Core', TechnologyLayer.backend, Confidence.medium, 'Kestrel or ASP.NET Core cookie marker');
    }
    if (observation.header('x-aspnet-version').isNotEmpty || cookies.contains('asp.net_sessionid=')) {
      add('ASP.NET (legacy)', TechnologyLayer.backend, Confidence.medium, 'ASP.NET version or session marker');
    } else if (powered.contains('asp.net')) {
      add('ASP.NET (family)', TechnologyLayer.backend, Confidence.low, 'Generic ASP.NET header');
    }
    if (server.contains('gunicorn') || server.contains('uvicorn') || server.contains('werkzeug')) {
      add('Python (likely)', TechnologyLayer.backend, Confidence.medium, 'Python server marker');
    }
    if (cookies.contains('csrftoken=') && cookies.contains('sessionid=')) {
      add('Django (possible)', TechnologyLayer.backend, Confidence.low, 'Common Django cookie names');
    }
    if (server.contains('werkzeug') || powered.contains('flask')) {
      add('Flask (possible)', TechnologyLayer.backend, Confidence.low, 'Werkzeug server marker');
    }
    if (powered.contains('fastapi') || (body.contains('fastapi') && body.contains('swagger-ui'))) {
      add('FastAPI (likely)', TechnologyLayer.backend, Confidence.medium, 'Framework-specific header or documentation marker');
    }
    if (powered.contains('django') || body.contains('django version:')) {
      add('Django', TechnologyLayer.backend, Confidence.medium, 'Framework-specific header or page marker');
    }
    if (powered.contains('spring boot') || body.contains('spring boot actuator')) {
      add('Spring Boot', TechnologyLayer.backend, Confidence.medium, 'Framework-specific header or documentation marker');
    }
    if (powered.contains('nestjs') || powered.contains('nest.js')) {
      add('NestJS', TechnologyLayer.backend, Confidence.medium, 'NestJS header');
    }
    if (powered.contains('node.js') || powered.contains('nodejs')) {
      add('Node.js', TechnologyLayer.backend, Confidence.medium, 'Runtime-specific header');
    }
    if (RegExp(r'^go(?:/|\s|$)').hasMatch(powered) || server.contains('go-http-server')) {
      add('Go (possible)', TechnologyLayer.backend, Confidence.low, 'Go-specific header marker');
    }
    if (powered.contains('express')) {
      add('Express / Node.js', TechnologyLayer.backend, Confidence.medium, 'Express header');
    }
    if (powered.contains('servlet') || cookies.contains('jsessionid=')) {
      add('Java servlet (likely)', TechnologyLayer.backend, Confidence.medium, 'Servlet header or session cookie');
    }
    if (powered.contains('phusion passenger')) {
      add('Passenger', TechnologyLayer.server, Confidence.medium, 'Passenger header');
    }
    if (cookies.contains('_rails_session=') || powered.contains('ruby on rails')) {
      add('Ruby on Rails (possible)', TechnologyLayer.backend, Confidence.low, 'Rails session cookie marker');
    }

    if (powered.contains('next.js') || anyBody(['/_next/static/', '__next_data__'])) {
      add('Next.js', TechnologyLayer.frontend, Confidence.medium, 'Next.js header or page marker');
    }
    if (anyBody(['data-reactroot', 'data-reactid'])) {
      add('React', TechnologyLayer.frontend, Confidence.medium, 'React markup');
    }
    if (anyBody(['ng-version=', '_ngcontent-', '_nghost-'])) {
      add('Angular', TechnologyLayer.frontend, Confidence.medium, 'Angular markup');
    }
    if (anyBody(['data-v-app', '__vue__'])) {
      add('Vue', TechnologyLayer.frontend, Confidence.medium, 'Vue markup');
    }
    if (anyBody(['data-sveltekit', '/_app/immutable/'])) {
      add('SvelteKit', TechnologyLayer.frontend, Confidence.medium, 'Frontend asset marker');
    }
    if (anyBody(['__nuxt__', '/_nuxt/'])) {
      add('Nuxt', TechnologyLayer.frontend, Confidence.medium, 'Nuxt page marker');
    }
    if (anyBody(['swagger-ui', 'swaggerui', '"openapi":'])) {
      add('OpenAPI / Swagger (possible)', TechnologyLayer.api, Confidence.medium, 'API documentation marker');
    }

    return List.unmodifiable(results);
  }
}
