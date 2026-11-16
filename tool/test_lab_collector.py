import http.client
import json
import os
import threading
import time
import unittest
import ssl
from unittest.mock import patch

from lab_collector import Collector, create_tls_context


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.token = "x" * 32
        self.server = Collector(self.token, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join()

    def request(self, method, body=None, auth=True, path="/events"):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + self.token
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_authenticated_round_trip(self):
        data = {"label": "a" * 32, "protocol": "https"}
        self.assertEqual(self.request("POST", json.dumps(data))[0], 204)
        status, raw = self.request("GET")
        self.assertEqual(status, 200)
        event, = json.loads(raw)
        self.assertEqual(set(event), {"label", "protocol", "observedAt"})
        self.assertEqual(event["label"], data["label"])

    def test_reject_unauthorized_and_extra_fields(self):
        self.assertEqual(self.request("GET", auth=False)[0], 401)
        self.assertEqual(self.request("POST", "{}", auth=False)[0], 401)
        data = {"label": "a" * 32, "protocol": "https", "body": "raw"}
        self.assertEqual(self.request("POST", json.dumps(data))[0], 400)
        self.assertEqual(self.request("GET", path="/events?token=fixture")[0], 404)
        self.assertEqual(json.loads(self.request("GET")[1]), [])

    def test_bounded_retention(self):
        for i in range(205):
            self.server.events.append((time.monotonic() - 3601, {"label": str(i)}))
        self.assertEqual(len(self.server.events), 200)
        self.assertEqual(json.loads(self.request("GET")[1]), [])


class CollectorTlsConfigTests(unittest.TestCase):
    def test_tls_is_optional_and_partial_configuration_rejected(self):
        self.assertIsNone(create_tls_context({}))
        for env in ({"ODIN_LAB_TLS_CERT": "cert.pem"}, {"ODIN_LAB_TLS_KEY": "key.pem"}):
            with self.assertRaises(ValueError):
                create_tls_context(env)

    @patch("lab_collector.ssl.SSLContext")
    def test_tls_configuration_loads_only_explicit_operator_certificate(self, factory):
        context = create_tls_context({"ODIN_LAB_TLS_CERT": "lab.pem", "ODIN_LAB_TLS_KEY": "lab-key.pem"})
        factory.assert_called_once_with(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain.assert_called_once_with(certfile="lab.pem", keyfile="lab-key.pem")
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)


@unittest.skipUnless(all(os.environ.get(k) for k in (
    "ODIN_LAB_TEST_CERT", "ODIN_LAB_TEST_KEY", "ODIN_LAB_TEST_CA")),
    "Supply an operator-owned localhost test certificate, key and trust anchor.")
class CollectorTlsRoundTripTests(unittest.TestCase):
    def test_trusted_local_tls_connection(self):
        context = create_tls_context({
            "ODIN_LAB_TLS_CERT": os.environ["ODIN_LAB_TEST_CERT"],
            "ODIN_LAB_TLS_KEY": os.environ["ODIN_LAB_TEST_KEY"],
        })
        client_context = ssl.create_default_context(cafile=os.environ["ODIN_LAB_TEST_CA"])
        with Collector("x" * 32, port=0, tls_context=context) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                def call(method, body=None):
                    connection = http.client.HTTPSConnection("localhost", server.server_port,
                        context=client_context, timeout=5)
                    try:
                        connection.request(method, "/events", body, {
                            "Content-Type": "application/json", "Authorization": "Bearer " + "x" * 32})
                        response = connection.getresponse()
                        return response.status, response.read()
                    finally:
                        connection.close()
                self.assertEqual(call("POST", json.dumps({"label": "a" * 32, "protocol": "http"}))[0], 400)
                self.assertEqual(call("POST", json.dumps({"label": "a" * 32, "protocol": "https"}))[0], 204)
                status, body = call("GET")
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)[0]["protocol"], "https")
            finally:
                server.shutdown()
                worker.join()


if __name__ == "__main__":
    unittest.main()
