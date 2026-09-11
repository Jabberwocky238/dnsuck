import base64
from pathlib import Path
import unittest
import dns.message
from fixtures import inputs, expected_rrsets, write
from support import Server, ROOT


class DoHTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server()
        cls.addClassCleanup(cls.server.close)
        write(cls.server.binary, cls.server.args, inputs())

    def test_get_post_all_record_types_http2(self):
        for expected in expected_rrsets():
            name = expected.name
            for method in ("GET", "POST"):
                with self.subTest(name=str(name), kind=expected.rdtype, method=method):
                    message = dns.message.make_query(name, expected.rdtype)
                    wire = message.to_wire()
                    if method == "GET":
                        encoded = base64.urlsafe_b64encode(wire).decode().rstrip("=")
                        result = self.server.client.get(self.server.url + "/dns-query", params={"dns": encoded})
                    else:
                        result = self.server.client.post(self.server.url + "/dns-query", content=wire,
                            headers={"content-type": "application/dns-message"})
                    self.assertEqual(result.status_code, 200, result.text if result.status_code != 200 else "")
                    self.assertEqual(result.http_version, "HTTP/2")
                    self.assertEqual(result.headers["content-type"], "application/dns-message")
                    response = dns.message.from_wire(result.content)
                    self.assertEqual(response.question, message.question)
                    self.assertEqual(response.id, message.id)
                    actual = next(r for r in response.answer if r.rdtype == expected.rdtype)
                    self.assertEqual(set(actual), set(expected))
                    self.assertEqual(actual.ttl, expected.ttl)

    def test_rejects_invalid_http_and_dns(self):
        url = self.server.url + "/dns-query"
        for result, status in [
            (self.server.client.get(url), 400),
            (self.server.client.get(url, params={"dns": "not!base64"}), 400),
            (self.server.client.get(url + "?dns=AA&dns=AA"), 400),
            (self.server.client.put(url), 405),
            (self.server.client.post(url, content=b"garbage"), 415),
            (self.server.client.post(url, content=b"garbage", headers={"content-type": "application/dns-message"}), 400),
            (self.server.client.post(url, content=b"x" * 65536, headers={"content-type": "application/dns-message"}), 413),
        ]:
            self.assertEqual(result.status_code, status)

    def test_tls_certificate_verification(self):
        import httpx
        with httpx.Client(trust_env=False) as client:
            with self.assertRaises(httpx.ConnectError):
                client.get(self.server.url + "/dns-query")
