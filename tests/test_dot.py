import socket
import ssl
import unittest

from encrypted import EncryptedDNSTests


class DoTTests(EncryptedDNSTests, unittest.TestCase):
    transport = "dot"

    def test_alpn_and_reused_connection(self):
        import dns.message
        import dns.query
        context = ssl.create_default_context(cafile=str(self.server.cert))
        context.set_alpn_protocols(["dot"])
        with socket.create_connection(("127.0.0.1", self.server.dot_port), timeout=3) as tcp:
            with context.wrap_socket(tcp, server_hostname="localhost") as tls:
                self.assertEqual(tls.selected_alpn_protocol(), "dot")
                for kind in ("A", "AAAA", "A"):
                    query = dns.message.make_query("example.test", kind)
                    reply = dns.query.tls(query, "127.0.0.1", sock=tls, timeout=3)
                    self.assertEqual(reply.question, query.question)
                    self.assertTrue(reply.answer)
