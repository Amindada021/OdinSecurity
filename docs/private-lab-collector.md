# Private laboratory collector

The companion Python 3 standard-library receiver is an operator-owned fixture
service, not a public callback service. It binds only to 127.0.0.1:8765.
Both GET and POST /events require the same bearer secret (32–128 URL-safe
characters). No DNS listener, raw traffic capture, payload hosting, target
injection or automated remote probes are supported.

1. Set the ODIN_LAB_TOKEN environment variable to a securely generated
   random secret. Never commit it or put it in a URL.
2. Run python tool/lab_collector.py on your private lab machine.
3. If accessing it from another lab device, use an access-controlled private
   HTTPS reverse proxy with a trusted certificate. Do not expose the receiver
   publicly. Disable proxy request-body and authorization-header logging.
4. Use an explicitly authorized synthetic test client to POST ordinary JSON
   to /events with Content-Type: application/json and the bearer in the
   Authorization header. The only accepted fields are label (32 lowercase hex
   characters) and protocol (http or https). The receiver supplies a UTC
   timestamp; data is limited to 200 events and one hour in memory.
5. Register the exact HTTPS export endpoint in Odin Security, choose Remote
   lab metadata review, enter the bearer, and approve one GET. Compare the
   locally generated correlation label with the fixture event. Credentials
   are not saved by this screen. Correlation is not proof of a vulnerability.

Local companion tests: python -m unittest discover -s tool -p test_lab_collector.py
