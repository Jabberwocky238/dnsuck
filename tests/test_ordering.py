"""Per-RRset ordering preserves complete answers, including DNSSEC validity."""
import asyncio
import concurrent.futures
import unittest

import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rrset

from fixtures import record
from support import quic_query, ROOT, Server


class OrderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(signed=True, encrypted_dns=True, mmdb=ROOT / "tests/data/country.mmdb")
        cls.addClassCleanup(cls.server.close)
        cls.origin = dns.name.from_text("secure.test.")
        anchor = dns.dnssec.make_dnskey(cls.server.signing_key.public_key(), "ECDSAP256SHA256", flags=257)
        cls.keys = {cls.origin: dns.rrset.from_rdata(cls.origin, 300, anchor)}

    def write(self, name, mode, kind="A"):
        addresses = [f"192.0.2.{i}" if kind == "A" else f"2001:db8::{i}" for i in (1, 2, 3)]
        response = self.server.graphql("mutation($r:[RecordInput!]!,$mode:OrderMode){upsert(records:$r,mode:$mode)}",
            {"r":[record(name, kind, value) for value in addresses], "mode":mode})
        self.assertNotIn("errors", response.json(), response.text)
        return addresses

    def query(self, name, transport="udp", kind="A"):
        query = dns.message.make_query(name, kind, want_dnssec=True)
        if transport == "udp":
            return dns.query.udp(query, "127.0.0.1", port=self.server.port, timeout=3)
        if transport == "tcp":
            return dns.query.tcp(query, "127.0.0.1", port=self.server.port, timeout=3)
        if transport == "dot":
            return dns.query.tls(query, "127.0.0.1", port=self.server.dot_port, timeout=3,
                verify=str(self.server.cert), server_hostname="localhost")
        if transport == "doq":
            return asyncio.run(quic_query(query, "127.0.0.1", port=self.server.doq_port, timeout=3,
                verify=str(self.server.cert), server_hostname="localhost"))
        response = self.server.client.post(self.server.url + "/dns-query", content=query.to_wire(),
            headers={"content-type":"application/dns-message"})
        return dns.message.from_wire(response.content)

    def addresses(self, reply, expected, signed=False, kind="A"):
        rrset = next(r for r in reply.answer if r.rdtype == dns.rdatatype.from_text(kind))
        addresses = [r.address for r in rrset]
        self.assertEqual(set(addresses), set(expected))
        self.assertEqual(len(addresses), len(expected))
        if signed:
            signature = next(r for r in reply.answer if r.rdtype == dns.rdatatype.RRSIG and r.covers == rrset.rdtype and r.name == rrset.name)
            dns.dnssec.validate(rrset, signature, self.keys)
        return addresses

    def test_lb_all_transports_and_dnssec(self):
        for transport in ("udp", "tcp", "doh", "dot", "doq"):
            for suffix in ("test.", "secure.test."):
                name = f"lb-{transport}.{suffix}"
                expected = self.write(name, "LB")
                orders = [self.addresses(self.query(name, transport), expected, suffix == "secure.test.") for _ in range(3)]
                self.assertEqual(orders, [expected, expected[1:] + expected[:1], expected[2:] + expected[:2]])

    def test_geo_ipv4_ipv6_and_signatures(self):
        for kind in ("A", "AAAA"):
            for transport in ("udp", "tcp", "doh", "dot", "doq"):
                name = f"geo-{kind.lower()}-{transport}.secure.test."
                expected = self.write(name, "GEO", kind)
                order = self.addresses(self.query(name, transport, kind), expected, True, kind)
                self.assertEqual(order[0], expected[1])

    def test_random_retains_all_records_and_valid_signatures(self):
        name = "random.secure.test."
        expected = self.write(name, "RANDOM")
        orders = {tuple(self.addresses(self.query(name), expected, True)) for _ in range(20)}
        self.assertGreater(len(orders), 1)

    def test_lb_concurrency_and_restart(self):
        name = "parallel.test."
        expected = self.write(name, "LB")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            replies = list(executor.map(lambda _: self.query(name), range(24)))
        for reply in replies:
            self.addresses(reply, expected)
        # A restart preserves the policy and values but resets the memory-only cursor.
        self.query(name)
        self.server.stop()
        self.server.start()
        self.assertEqual(self.addresses(self.query(name), expected), expected)

    def test_cname_and_policy_deletion(self):
        expected = self.write("target.test.", "GEO")
        self.server.upsert([record("ordered-alias.test.", "CNAME", "target.test.")])
        reply = self.query("ordered-alias.test.")
        self.assertEqual(reply.answer[0].rdtype, dns.rdatatype.CNAME)
        self.assertEqual(self.addresses(reply, expected)[0], expected[1])
        self.assertEqual(self.server.graphql('mutation{delete(name:"target.test",recordType:"A")}').json()["data"]["delete"], 3)
        self.server.upsert([record("target.test.", "A", value) for value in expected])
        self.assertEqual(self.addresses(self.query("target.test."), expected), expected)

    def test_geo_requires_database_and_address_records(self):
        response = self.server.graphql('mutation{upsert(records:[{name:"geo-txt.test",recordType:"TXT",ttl:300,data:"hello"}],mode:GEO)}')
        self.assertIn("errors", response.json())
        server = Server(management_only=True)
        try:
            response = server.graphql('mutation{add(records:[{name:"geo.test",recordType:"A",ttl:300,data:"192.0.2.1"}],mode:GEO)}')
            self.assertIn("errors", response.json())
            self.assertIn("mmdb", str(response.json()))
        finally:
            server.close()
