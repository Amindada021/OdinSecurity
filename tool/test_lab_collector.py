import http.client
import json
import threading
import time
import unittest

from lab_collector import Collector


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


if __name__ == "__main__":
    unittest.main()
