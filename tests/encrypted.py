"""Shared assertions for the independent DoT and DoQ clients."""
import concurrent.futures
import socket
import ssl

import asyncio
import dns.asyncquery
import dns.quic
from dns.quic._common import UnexpectedEOF
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode

from fixtures import expected_rrsets, inputs, record, write
from support import Server


class EncryptedDNSTests:
    @classmethod
    def setUpClass(cls):
        cls.server = Server(encrypted_dns=True)
        cls.addClassCleanup(cls.server.close)
        write(cls.server.binary, cls.server.args, inputs())

    def query(self, name, kind, verify=None, hostname="localhost"):
        message = dns.message.make_query(name, kind)
        if verify is None:
            verify = str(self.server.cert)
        if self.transport == "dot":
            response = dns.query.tls(message, "127.0.0.1", port=self.server.dot_port,
                timeout=2, server_hostname=hostname, verify=verify)
        else:
            response = asyncio.run(dns.asyncquery.quic(message, "127.0.0.1", port=self.server.doq_port,
                timeout=2, server_hostname=hostname, verify=verify))
            self.assertEqual(response.id, 0)
        self.assertEqual(response.question, message.question)
        self.assertEqual(response.id, message.id)
        self.assertTrue(response.flags & dns.flags.QR)
        return response

    def test_all_record_types(self):
        for expected in expected_rrsets():
            with self.subTest(name=str(expected.name), kind=expected.rdtype):
                reply = self.query(str(expected.name), expected.rdtype)
                self.assertEqual(reply.rcode(), dns.rcode.NOERROR)
                actual = next(r for r in reply.answer if r.rdtype == expected.rdtype)
                self.assertEqual(actual.ttl, expected.ttl)
                self.assertEqual(set(actual), set(expected))

    def test_negative_and_live_updates(self):
        self.assertEqual(self.query("missing.test", "A").rcode(), dns.rcode.NXDOMAIN)
        reply = self.query("example.test", "MX")
        self.assertEqual(reply.rcode(), dns.rcode.NOERROR)
        self.assertFalse(reply.answer)
        self.server.upsert([record("live.test", "A", "192.0.2.78", 45)])
        reply = self.query("live.test", "A")
        self.assertEqual(reply.answer[0][0].address, "192.0.2.78")
        self.assertEqual(reply.answer[0].ttl, 45)
        self.server.upsert([record("live.test", "A", "192.0.2.79", 90)])
        self.assertEqual(self.query("live.test", "A").answer[0][0].address, "192.0.2.79")

    def test_rejects_untrusted_certificate_and_wrong_hostname(self):
        for verify, hostname in [(True, "localhost"), (str(self.server.cert), "wrong.example")]:
            with self.subTest(hostname=hostname):
                with self.assertRaises((ssl.SSLError, dns.exception.DNSException, ConnectionError, UnexpectedEOF)):
                    self.query("example.test", "A", verify, hostname)
        # Failed handshakes must not stop the listener.
        self.assertEqual(self.query("example.test", "A").rcode(), dns.rcode.NOERROR)

    def test_concurrent_requests_and_large_answers(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            replies = list(executor.map(lambda _: self.query("example.test", "A"), range(12)))
        self.assertTrue(all(r.answer[0][0].address == "192.0.2.10" for r in replies))
        self.server.upsert([record("large.test", "TXT", f'"{i}{"x" * 200}"') for i in range(6)])
        reply = self.query("large.test", "TXT")
        self.assertFalse(reply.flags & dns.flags.TC)
        self.assertEqual(len(reply.answer[0]), 6)
