"""Independent DNS wire-level integration tests using dnspython."""
import concurrent.futures
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import unittest


import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rcode
import dns.rdatatype
from fixtures import record, inputs, expected_rrsets, write


class DnsIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get("DNS_TEST_BINARY", str(
            Path(__file__).resolve().parents[1] / "target/debug/dnsuck"))
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.args = ["--graphql", "--listen", "127.0.0.1:0", "--database", cls.temp.name, "--dns", f"127.0.0.1:{cls.port}"]
        cls.put("example.test", "192.0.2.10", 60)
        cls.put("example.test", "2001:db8::10", 120)
        cls.put("v4.test", "192.0.2.20", 30)
        cls.start()
        cls.addClassCleanup(cls.stop)

    @classmethod
    def put(cls, name, ip, ttl):
        subprocess.run([cls.binary, *cls.args, "put", name, ip, str(ttl)],
                       check=True, capture_output=True, text=True, timeout=10)

    @classmethod
    def start(cls):
        cls.process = subprocess.Popen([cls.binary, *cls.args],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.process.poll() is not None:
                raise AssertionError(cls.process.communicate())
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.02)
        cls.stop()
        raise AssertionError("DNS server did not become ready")

    @classmethod
    def stop(cls):
        if cls.process.poll() is None:
            cls.process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = cls.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            cls.process.kill()
            cls.process.communicate()
            raise AssertionError("DNS server did not shut down")
        if cls.process.returncode != 0:
            raise AssertionError((stdout, stderr))

    def exchange(self, name="example.test", kind=1, tcp=False, qclass=1, opcode=0):
        message = dns.message.make_query(name, kind, qclass)
        message.set_opcode(opcode)
        response = (dns.query.tcp if tcp else dns.query.udp)(
            message, "127.0.0.1", port=self.port, timeout=3)
        self.assertEqual(response.id, message.id)
        self.assertTrue(response.flags & dns.flags.QR)
        self.assertTrue(response.flags & dns.flags.RD)
        self.assertFalse(response.flags & dns.flags.RA)
        self.assertEqual(response.question, message.question)
        return response

    def query(self, name="example.test", kind=1, tcp=False, qclass=1, opcode=0):
        response = self.exchange(name, kind, tcp, qclass, opcode)
        answers = [(rrset.rdtype, rrset.ttl, record.to_text())
                   for rrset in response.answer for record in rrset]
        return response.rcode(), answers

    def test_all_fixture_record_types(self):
        write(self.binary, self.args, inputs())
        for expected in expected_rrsets():
            for tcp in (False, True):
                with self.subTest(name=str(expected.name), kind=expected.rdtype, tcp=tcp):
                    reply = self.exchange(str(expected.name), expected.rdtype, tcp)
                    self.assertEqual(reply.rcode(), dns.rcode.NOERROR)
                    actual = next(r for r in reply.answer if r.rdtype == expected.rdtype)
                    self.assertEqual(actual.ttl, expected.ttl)
                    self.assertEqual(set(actual), set(expected))
        # Restore the original test data overwritten by the fixture.
        self.put("example.test", "192.0.2.10", 60)
        self.put("example.test", "2001:db8::10", 120)
        for tcp in (False, True):
            response = self.exchange("alias.test", "A", tcp)
            self.assertEqual([r.rdtype for r in response.answer],
                             [dns.rdatatype.CNAME, dns.rdatatype.A])
            self.assertEqual({r.rdtype for r in self.exchange("example.test", "ANY", tcp).answer},
                             {dns.rdatatype.A, dns.rdatatype.AAAA})

    def test_udp_tcp_ipv4_ipv6_and_case(self):
        for tcp in (False, True):
            with self.subTest(tcp=tcp):
                self.assertEqual(self.query("ExAmPlE.TeSt.", tcp=tcp),
                                 (0, [(1, 60, "192.0.2.10")]))
                self.assertEqual(self.query(kind=28, tcp=tcp),
                                 (0, [(28, 120, "2001:db8::10")]))

    def test_negative_and_unsupported_queries(self):
        for tcp in (False, True):
            self.assertEqual(self.query("missing.test", tcp=tcp), (3, []))
            self.assertEqual(self.query("v4.test", kind=28, tcp=tcp), (0, []))
            self.assertEqual(self.query(kind=16, tcp=tcp), (0, []))
            self.assertEqual(self.query(qclass=3, tcp=tcp), (5, []))
            self.assertEqual(self.query(opcode=4, tcp=tcp), (4, []))

    def test_live_updates_and_restart(self):
        self.put("live.test", "192.0.2.30", 45)
        self.assertEqual(self.query("live.test"), (0, [(1, 45, "192.0.2.30")]))
        self.put("LIVE.test.", "192.0.2.31", 90)
        self.assertEqual(self.query("live.test", tcp=True), (0, [(1, 90, "192.0.2.31")]))
        self.stop()
        self.start()
        self.assertEqual(self.query("live.test"), (0, [(1, 90, "192.0.2.31")]))

    def test_large_answer_tcp_fallback(self):
        records = [record("large.test.", "TXT", f'"{i}{"x" * 200}"', 60) for i in range(6)]
        write(self.binary, self.args, records)
        message = dns.message.make_query("large.test", "TXT")
        reply, used_tcp = dns.query.udp_with_fallback(message, "127.0.0.1", port=self.port, timeout=3)
        self.assertTrue(used_tcp)
        self.assertEqual(reply.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(reply.answer[0]), 6)

    def test_cname_cycle_servfail_and_empty_question(self):
        write(self.binary, self.args, [record("loop1.test.", "CNAME", "loop2.test.", 60),
                                      record("loop2.test.", "CNAME", "loop1.test.", 60)])
        self.assertEqual(self.query("loop1.test"), (2, []))
        message = dns.message.Message(id=4321)
        reply = dns.query.udp(message, "127.0.0.1", port=self.port, timeout=3)
        self.assertEqual(reply.rcode(), dns.rcode.FORMERR)
        self.assertEqual(self.query("example.test"), (0, [(1, 60, "192.0.2.10")]))

    def test_concurrent_queries(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda n: self.query(tcp=bool(n % 2)), range(48)))
        self.assertTrue(all(result == (0, [(1, 60, "192.0.2.10")]) for result in results))


if __name__ == "__main__":
    unittest.main(verbosity=2)
