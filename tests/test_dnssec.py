import unittest
import asyncio
import dns.asyncquery
import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
from support import Server
from fixtures import record


class DNSSECTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(signed=True, encrypted_dns=True)
        cls.addClassCleanup(cls.server.close)
        cls.origin = dns.name.from_text("secure.test.")
        # Trust the public half of the locally generated key, not a key fetched blindly.
        anchor = dns.dnssec.make_dnskey(cls.server.signing_key.public_key(), "ECDSAP256SHA256", flags=257)
        cls.keys = {cls.origin: dns.rrset.from_rdata(cls.origin, 300, anchor)}

    def query(self, name, kind, transport="udp", do=True):
        message = dns.message.make_query(name, kind, want_dnssec=do)
        if transport == "dot":
            return dns.query.tls(message, "127.0.0.1", port=self.server.dot_port, timeout=5,
                                 server_hostname="localhost", verify=str(self.server.cert))
        if transport == "doq":
            return asyncio.run(dns.asyncquery.quic(message, "127.0.0.1", port=self.server.doq_port, timeout=5,
                                  server_hostname="localhost", verify=str(self.server.cert)))
        if transport == "doh":
            result = self.server.client.post(self.server.url + "/dns-query", content=message.to_wire(),
                headers={"content-type":"application/dns-message"})
            self.assertEqual(result.status_code, 200)
            return dns.message.from_wire(result.content)
        return (dns.query.tcp if transport == "tcp" else dns.query.udp)(message, "127.0.0.1", port=self.server.port, timeout=5)

    def validate_section(self, section):
        count = 0
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.RRSIG:
                continue
            sig = next(r for r in section if r.name == rrset.name and r.rdtype == dns.rdatatype.RRSIG and r.covers == rrset.rdtype)
            dns.dnssec.validate(rrset, sig, self.keys)
            count += 1
        self.assertGreater(count, 0)

    def test_signatures_dnskey_and_do_bit(self):
        for transport in ("udp", "tcp", "doh", "dot", "doq"):
            for name, kind in [("host.secure.test", "A"), ("host.secure.test", "AAAA"),
                               ("text.secure.test", "TXT"), ("secure.test", "DNSKEY"),
                               ("alias.secure.test", "A")]:
                with self.subTest(transport=transport, kind=kind):
                    reply = self.query(name, kind, transport)
                    self.assertEqual(reply.rcode(), dns.rcode.NOERROR)
                    self.assertTrue(reply.flags & dns.flags.AA)
                    self.assertFalse(reply.flags & dns.flags.AD)
                    self.validate_section(reply.answer)
            plain = self.query("host.secure.test", "A", transport, do=False)
            self.assertTrue(all(r.rdtype != dns.rdatatype.RRSIG for r in plain.answer))

    def test_signed_nxdomain_and_nodata(self):
        for transport in ("udp", "tcp", "doh", "dot", "doq"):
            missing = dns.name.from_text("missing.secure.test.")
            reply = self.query(str(missing), "A", transport)
            self.assertEqual(reply.rcode(), dns.rcode.NXDOMAIN)
            self.validate_section(reply.authority)
            nsecs = [r for r in reply.authority if r.rdtype == dns.rdatatype.NSEC]
            self.assertTrue(nsecs)
            def covered(rrset):
                end = rrset[0].next
                return rrset.name < missing < end if rrset.name < end else missing > rrset.name or missing < end
            self.assertTrue(any(covered(r) for r in nsecs))
            reply = self.query("host.secure.test", "MX", transport)
            self.assertEqual(reply.rcode(), dns.rcode.NOERROR)
            self.assertFalse(reply.answer)
            self.validate_section(reply.authority)
            proof = next(r for r in reply.authority if r.rdtype == dns.rdatatype.NSEC and str(r.name) == "host.secure.test.")
            self.assertNotIn("MX", proof[0].to_text().split()[1:])

    def test_update_resigns_and_restart_preserves_key(self):
        self.server.upsert([record("updated.secure.test.", "A", "192.0.2.99", 60)])
        reply = self.query("updated.secure.test", "A", "doh")
        self.validate_section(reply.answer)
        self.assertEqual(reply.answer[0][0].address, "192.0.2.99")
        # A separate writer invalidates the cached zone by its LMDB revision too.
        self.server.run("put", "updated.secure.test", "192.0.2.100", "60")
        reply = self.query("updated.secure.test", "A")
        self.validate_section(reply.answer)
        self.assertEqual(reply.answer[0][0].address, "192.0.2.100")
        self.server.stop()
        self.server.start()
        self.validate_section(self.query("secure.test", "DNSKEY").answer)
        result = self.server.graphql('mutation{delete(name:"secure.test",recordType:"SOA")}').json()
        self.assertIn("errors", result)
        result = self.server.graphql('mutation{delete(name:"updated.secure.test")}').json()
        self.assertEqual(result["data"]["delete"], 1)
        reply = self.query("updated.secure.test", "A")
        self.assertEqual(reply.rcode(), dns.rcode.NXDOMAIN)
        self.validate_section(reply.authority)
