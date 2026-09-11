"""Plaintext backends for proxies that terminate DoH/DoT TLS."""
import base64
import unittest
import dns.message
import dns.query
from fixtures import expected_rrsets, inputs, write
from support import Server


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(encrypted_dns=True, proxy=True)
        cls.addClassCleanup(cls.server.close)
        write(cls.server.binary, cls.server.args, inputs())

    def test_plain_http_and_tcp_all_types(self):
        for expected in expected_rrsets():
            with self.subTest(name=str(expected.name), kind=expected.rdtype):
                query = dns.message.make_query(expected.name, expected.rdtype)
                url = self.server.url + "/dns-query"
                encoded = base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode()
                get = self.server.client.get(url, params={"dns": encoded})
                post = self.server.client.post(url, content=query.to_wire(),
                    headers={"content-type": "application/dns-message"})
                self.assertEqual(get.status_code, 200)
                self.assertEqual(post.status_code, 200)
                replies = [dns.message.from_wire(get.content), dns.message.from_wire(post.content),
                    dns.query.tcp(query, "127.0.0.1", port=self.server.dot_port, timeout=2)]
                for reply in replies:
                    actual = next(r for r in reply.answer if r.rdtype == expected.rdtype)
                    self.assertEqual(set(actual), set(expected))
                    self.assertEqual(actual.ttl, expected.ttl)

    def test_management_remains_separate(self):
        self.assertEqual(self.server.client.get(self.server.url + "/graphql").status_code, 404)
        self.assertEqual(self.server.graphql("{names}").status_code, 200)
