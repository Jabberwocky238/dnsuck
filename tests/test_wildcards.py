"""Single-label wildcard templates across DNS transports, storage and management."""
import asyncio
import os
import subprocess
import unittest

import dns.asyncquery
import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset

from fixtures import inputs, record
from support import ROOT, Server


class WildcardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server(signed=True, encrypted_dns=True, mmdb=ROOT / "tests/data/country.mmdb")
        cls.addClassCleanup(cls.server.close)
        origin = dns.name.from_text("secure.test.")
        anchor = dns.dnssec.make_dnskey(cls.server.signing_key.public_key(), "ECDSAP256SHA256", flags=257)
        cls.keys = {origin: dns.rrset.from_rdata(origin, 300, anchor)}

    def query(self, name, kind="A", transport="udp"):
        query = dns.message.make_query(name, kind, want_dnssec=True)
        if transport == "doh":
            response = self.server.client.post(self.server.url + "/dns-query", content=query.to_wire(),
                headers={"content-type": "application/dns-message"})
            self.assertEqual(response.status_code, 200)
            return dns.message.from_wire(response.content)
        if transport == "dot":
            return dns.query.tls(query, "127.0.0.1", port=self.server.dot_port, timeout=5,
                verify=str(self.server.cert), server_hostname="localhost")
        if transport == "doq":
            return asyncio.run(dns.asyncquery.quic(query, "127.0.0.1", port=self.server.doq_port, timeout=5,
                verify=str(self.server.cert), server_hostname="localhost"))
        return (dns.query.tcp if transport == "tcp" else dns.query.udp)(query, "127.0.0.1", port=self.server.port, timeout=5)

    def validate(self, section):
        for rrset in section:
            if rrset.rdtype != dns.rdatatype.RRSIG:
                signature = next(r for r in section if r.name == rrset.name and r.rdtype == dns.rdatatype.RRSIG and r.covers == rrset.rdtype)
                dns.dnssec.validate(rrset, signature, self.keys)

    def address(self, name, expected, transport="udp", signed=False):
        response = self.query(name, transport=transport)
        self.assertEqual(response.rcode(), dns.rcode.NOERROR, response)
        rrset = next(r for r in response.answer if r.rdtype == dns.rdatatype.A)
        self.assertEqual(rrset.name, dns.name.from_text(name))
        self.assertEqual([r.address for r in rrset], expected)
        if signed:
            self.validate(response.answer)
        return response

    def test_nested_patterns_and_signed_transports(self):
        for suffix in ("exp.com", "secure.test"):
            pattern = f"*.jjj.*.fff.*.{suffix}"
            self.server.upsert([record(pattern, "A", "192.0.2.1"), record(pattern, "A", "192.0.2.2")])
            for transport in ("udp", "tcp", "doh", "dot", "doq"):
                with self.subTest(suffix=suffix, transport=transport):
                    self.address(f"a.jjj.b.fff.c.{suffix}", ["192.0.2.1", "192.0.2.2"], transport, suffix == "secure.test")
            for name in (f"jjj.b.fff.c.{suffix}", f"a.x.jjj.b.fff.c.{suffix}", f"a.jjj.b.fff.{suffix}"):
                response = self.query(name)
                self.assertEqual(response.rcode(), dns.rcode.NXDOMAIN, response)
                if suffix == "secure.test":
                    self.validate(response.authority)
                    self.assertTrue(all(r.ttl == 0 for r in response.authority if r.rdtype == dns.rdatatype.NSEC))
                    soa = next(r for r in response.authority if r.rdtype == dns.rdatatype.SOA)
                    self.assertEqual(soa[0].minimum, 0)
            response = self.query(f"a.jjj.b.fff.c.{suffix}", "MX")
            self.assertEqual(response.rcode(), dns.rcode.NOERROR)
            self.assertFalse(response.answer)
            if suffix == "secure.test":
                self.validate(response.authority)

    def test_globstar_matches_one_or_more_labels_in_each_position(self):
        for suffix in ("example.com", "secure.test"):
            pattern = f"**.dfsdfsdf.**.{suffix}"
            self.server.upsert([record(pattern, "A", "192.0.2.5")])
            for transport in ("udp", "tcp", "doh", "dot", "doq"):
                for name in (f"a.dfsdfsdf.b.{suffix}", f"a.b.dfsdfsdf.c.d.e.{suffix}"):
                    self.address(name, ["192.0.2.5"], transport, suffix == "secure.test")
            for name in (f"dfsdfsdf.{suffix}", f"a.dfsdfsdf.{suffix}", f"dfsdfsdf.a.{suffix}", f"a.other.b.{suffix}"):
                self.assertEqual(self.query(name).rcode(), dns.rcode.NXDOMAIN)
            query = self.server.graphql("query($name:String!){records(name:$name){name}}", {"name":pattern})
            self.assertEqual(query.json()["data"]["records"][0]["name"], pattern + ".")

    def test_globstar_single_star_and_exact_precedence(self):
        self.server.upsert([
            record("**.mixed.test", "A", "192.0.2.1"),
            record("*.mixed.test", "A", "192.0.2.2"),
            record("**.*.mixed.test", "A", "192.0.2.3"),
            record("exact.mixed.test", "A", "192.0.2.4"),
            record("**.**.adjacent-glob.test", "A", "192.0.2.5"),
        ])
        self.address("one.mixed.test", ["192.0.2.2"])
        self.address("a.b.c.mixed.test", ["192.0.2.3"])
        self.address("exact.mixed.test", ["192.0.2.4"])
        self.address("a.b.adjacent-glob.test", ["192.0.2.5"])
        self.address("a.b.c.d.adjacent-glob.test", ["192.0.2.5"])
        self.assertEqual(self.query("a.adjacent-glob.test").rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(self.query("mixed.test").rcode(), dns.rcode.NXDOMAIN)

    def test_precedence_and_no_type_fallback(self):
        for suffix in ("precedence.test", "precedence.secure.test"):
            self.server.upsert([
                record(f"*.*.{suffix}", "A", "192.0.2.1"),
                record(f"a.*.{suffix}", "A", "192.0.2.2"),
                record(f"*.b.{suffix}", "A", "192.0.2.3"),
                record(f"exact.b.{suffix}", "TXT", '"exact"'),
                record(f"*.txt.{suffix}", "TXT", '"specific"'),
            ])
            self.address(f"A.B.{suffix}", ["192.0.2.3"], signed="secure" in suffix)
            self.address(f"a.c.{suffix}", ["192.0.2.2"])
            for name in (f"exact.b.{suffix}", f"a.txt.{suffix}"):
                response = self.query(name)
                self.assertEqual(response.rcode(), dns.rcode.NOERROR)
                self.assertFalse(response.answer)

    def test_all_rdata_types_keep_payload_and_ttl(self):
        records = inputs()
        for index, value in enumerate(records):
            value["name"] = f"*.kind{index}.*.types.test"
        self.server.upsert(records)
        for index, value in enumerate(records):
            name = f"a.kind{index}.b.types.test"
            response = self.query(name, value["recordType"])
            stored = self.query(value["name"], value["recordType"])
            self.assertEqual(response.rcode(), dns.rcode.NOERROR, response)
            self.assertEqual(response.answer[0].name, dns.name.from_text(name))
            self.assertEqual(response.answer[0].ttl, value["ttl"])
            self.assertEqual(set(response.answer[0]), set(stored.answer[0]))

    def test_cname_targets_and_ordering(self):
        for suffix in ("chain.test", "chain.secure.test"):
            pattern = f"**.target.**.{suffix}"
            response = self.server.graphql("mutation($r:[RecordInput!]!){upsert(records:$r,mode:LB)}", {
                "r": [record(pattern, "A", "192.0.2.1"), record(pattern, "A", "192.0.2.2")]})
            self.assertNotIn("errors", response.json())
            self.server.upsert([record(f"*.alias.{suffix}", "CNAME", f"a.target.b.{suffix}.")])
            for index in range(2):
                response = self.query(f"x.alias.{suffix}")
                self.assertEqual(response.answer[0].name, dns.name.from_text(f"x.alias.{suffix}"))
                addresses = next(r for r in response.answer if r.rdtype == dns.rdatatype.A)
                self.assertEqual([r.address for r in addresses], ["192.0.2.1", "192.0.2.2"][index:] + ["192.0.2.1", "192.0.2.2"][:index])
                if "secure" in suffix:
                    self.validate(response.answer)
            # The in-memory lb cursor belongs to the template, even for another query name.
            self.address(f"other.deep.target.name.with.more.{suffix}", ["192.0.2.1", "192.0.2.2"])

    @unittest.skipUnless(os.environ.get("DNS_TEST_CLI"), "requires built management CLI")
    def test_cli_crud_restart_and_external_writer_invalidate_index(self):
        binary = os.environ["DNS_TEST_CLI"]
        pattern = "**.cli.**.wild.test"
        def cli(*args):
            return subprocess.run([binary, "--endpoint", self.server.graphql_url + "/graphql", *args],
                text=True, capture_output=True, check=True)
        self.assertEqual(self.query("a.cli.b.wild.test").rcode(), dns.rcode.NXDOMAIN)
        cli("put", pattern, "A", "192.0.2.1")
        cli("add", pattern, "A", "192.0.2.2")
        self.assertIn(pattern + ".", cli("get", pattern, "A").stdout)
        self.address("a.cli.b.wild.test", ["192.0.2.1", "192.0.2.2"])
        cli("del", pattern, "A", "192.0.2.1")
        self.address("a.cli.b.wild.test", ["192.0.2.2"])
        self.server.stop()
        self.server.start()
        self.address("a.cli.b.wild.test", ["192.0.2.2"])
        cli("del", pattern, "A")
        self.assertEqual(self.query("a.cli.b.wild.test").rcode(), dns.rcode.NXDOMAIN)
        self.server.run("put", pattern, "192.0.2.3", "300")
        self.address("a.cli.b.wild.test", ["192.0.2.3"])

    def test_adjacent_stars_middle_labels_and_literal_partial_stars(self):
        self.server.upsert([
            record("*.*.adjacent.test", "A", "192.0.2.1"),
            record("fixed.*.middle.test", "A", "192.0.2.2"),
        ])
        self.address("a.b.adjacent.test", ["192.0.2.1"])
        self.address("fixed.a.middle.test", ["192.0.2.2"])
        invalid = self.server.graphql('mutation{upsert(records:[{name:"partial*.literal.test",recordType:"A",ttl:300,data:"192.0.2.3"}])}')
        self.assertIn("errors", invalid.json())
        for name in ("a.adjacent.test", "a.b.c.adjacent.test", "other.a.middle.test", "partialx.literal.test"):
            self.assertEqual(self.query(name).rcode(), dns.rcode.NXDOMAIN)
        self.address(r"a\.b.c.adjacent.test", ["192.0.2.1"])
