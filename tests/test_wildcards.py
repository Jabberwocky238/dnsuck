"""Regex domain templates across DNS transports, storage and management."""
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

    def test_regex_segments_all_transports_and_signatures(self):
        for suffix in ("exp.com", "secure.test"):
            pattern = f"([a-z]+).jjj.([0-9]+).fff.(.+).{suffix}"
            self.server.upsert([record(pattern, "A", "192.0.2.1"), record(pattern, "A", "192.0.2.2")])
            for transport in ("udp", "tcp", "doh", "dot", "doq"):
                self.address(f"abc.jjj.123.fff.a.b.c.{suffix}", ["192.0.2.1", "192.0.2.2"], transport, suffix == "secure.test")
            for name in (f"123.jjj.123.fff.a.{suffix}", f"abc.jjj.abc.fff.a.{suffix}", f"abc.jjj.123.fff.{suffix}"):
                self.assertEqual(self.query(name).rcode(), dns.rcode.NXDOMAIN)
            response = self.query(f"abc.jjj.123.fff.a.{suffix}", "MX")
            self.assertEqual(response.rcode(), dns.rcode.NOERROR)
            self.assertFalse(response.answer)
            if suffix == "secure.test":
                self.validate(response.authority)
                self.assertTrue(all(r.ttl == 0 for r in response.authority if r.rdtype == dns.rdatatype.NSEC))

    def test_star_is_one_layer_and_regex_covers_multiple_layers(self):
        self.server.upsert([
            record("*.df.(.+).star.test", "A", "192.0.2.1"),
            record("([^.]+).single.test", "A", "192.0.2.2"),
            record("*.*.*.three.test", "A", "192.0.2.3"),
        ])
        self.address("a.df.c.d.e.star.test", ["192.0.2.1"])
        self.address("a.df.b.star.test", ["192.0.2.1"])
        self.address("a.single.test", ["192.0.2.2"])
        self.address("a.b.c.three.test", ["192.0.2.3"])
        self.address(r"a\.b.c.d.three.test", ["192.0.2.3"])
        for name in ("df.star.test", "a.df.star.test", "df.a.star.test", "a.b.single.test", "a.b.three.test", "a.b.c.d.three.test", "a.b.df.c.star.test"):
            self.assertEqual(self.query(name).rcode(), dns.rcode.NXDOMAIN)

    def test_nested_groups_classes_escapes_and_regex_case_are_preserved(self):
        self.server.upsert([
            record(r"((api|www)[0-9]{1,3}).nested.test", "A", "192.0.2.1"),
            record(r"(\D+).classes.test", "A", "192.0.2.2"),
            record(r"((?:a\.)+b).cross.test", "A", "192.0.2.3"),
            record(r"([a-z()]+).bracket.test", "A", "192.0.2.4"),
        ])
        self.address("API12.nested.test", ["192.0.2.1"])
        self.address("word.classes.test", ["192.0.2.2"])
        self.address("a.a.b.cross.test", ["192.0.2.3"])
        self.address("abc.bracket.test", ["192.0.2.4"])
        self.assertEqual(self.query("123.classes.test").rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(self.query("api1234.nested.test").rcode(), dns.rcode.NXDOMAIN)
        result = self.server.graphql("query($name:String!){records(name:$name){name}}", {"name":r"(\D+).classes.test"}).json()
        self.assertEqual(result["data"]["records"][0]["name"], r"(\D+).classes.test.")

    def test_exact_priority_literal_dots_and_no_type_fallback(self):
        self.server.upsert([
            record("(.+).priority.test", "A", "192.0.2.1"),
            record("(.+).specific.priority.test", "TXT", '"specific"'),
            record("exact.priority.test", "TXT", '"exact"'),
            record("([a-z]+).literal.test", "A", "192.0.2.2"),
        ])
        for name in ("exact.priority.test", "x.specific.priority.test"):
            response = self.query(name)
            self.assertEqual(response.rcode(), dns.rcode.NOERROR)
            self.assertFalse(response.answer)
        self.assertEqual(self.query("abclliteral.test").rcode(), dns.rcode.NXDOMAIN)
        self.address("abc.literal.test", ["192.0.2.2"])

    def test_cname_and_ordering_inherit_the_pattern(self):
        for suffix in ("chain.test", "chain.secure.test"):
            pattern = f"(.+).target.(.+).{suffix}"
            result = self.server.graphql("mutation($r:[RecordInput!]!){upsert(records:$r,mode:LB)}", {
                "r":[record(pattern, "A", "192.0.2.1"), record(pattern, "A", "192.0.2.2")]})
            self.assertNotIn("errors", result.json())
            self.server.upsert([record(f"*.alias.{suffix}", "CNAME", f"a.b.target.c.d.{suffix}.")])
            for index in range(2):
                response = self.query(f"x.alias.{suffix}")
                self.assertEqual(response.answer[0].name, dns.name.from_text(f"x.alias.{suffix}"))
                addresses = next(r for r in response.answer if r.rdtype == dns.rdatatype.A)
                expected = ["192.0.2.1", "192.0.2.2"]
                self.assertEqual([r.address for r in addresses], expected[index:] + expected[:index])
                if "secure" in suffix:
                    self.validate(response.answer)

    def test_all_record_types_keep_payload_and_ttl(self):
        import base64
        import dns.rdata
        records = inputs()
        for index, value in enumerate(records):
            value["name"] = f"([a-z]+).kind{index}.([0-9]+).types.test"
        self.server.upsert(records)
        for index, value in enumerate(records):
            name = f"abc.kind{index}.123.types.test"
            response = self.query(name, value["recordType"])
            raw = base64.b64decode(value["rdataBase64"])
            expected = dns.rdata.from_wire(1, dns.rdatatype.from_text(value["recordType"]), raw, 0, len(raw))
            self.assertEqual(response.rcode(), dns.rcode.NOERROR, response)
            self.assertEqual(response.answer[0].name, dns.name.from_text(name))
            self.assertEqual(response.answer[0].ttl, value["ttl"])
            self.assertEqual(set(response.answer[0]), {expected})

    @unittest.skipUnless(os.environ.get("DNS_TEST_CLI"), "requires built CLI")
    def test_cli_crud_restart_and_external_writer_invalidate_cache(self):
        pattern = "([a-z]+).cli.(.+).crud.test"
        def cli(*args):
            return subprocess.run([os.environ["DNS_TEST_CLI"], "--endpoint", self.server.graphql_url + "/graphql", *args],
                text=True, capture_output=True, check=True)
        self.assertEqual(self.query("a.cli.b.c.crud.test").rcode(), dns.rcode.NXDOMAIN)
        cli("put", pattern, "A", "192.0.2.1")
        cli("add", pattern, "A", "192.0.2.2")
        self.assertIn(pattern, cli("get", pattern, "A").stdout)
        self.address("a.cli.b.c.crud.test", ["192.0.2.1", "192.0.2.2"])
        cli("del", pattern, "A", "192.0.2.1")
        self.address("a.cli.b.c.crud.test", ["192.0.2.2"])
        self.server.stop()
        self.server.start()
        self.address("a.cli.b.c.crud.test", ["192.0.2.2"])
        cli("del", pattern, "A")
        self.assertEqual(self.query("a.cli.b.c.crud.test").rcode(), dns.rcode.NXDOMAIN)
        self.server.run("put", pattern, "192.0.2.3", "300")
        self.address("a.cli.b.c.crud.test", ["192.0.2.3"])
        cli("batch", "--item", 'put,"([a-z]{1,3}).batch.regex.test",A,192.0.2.4')
        self.address("abc.batch.regex.test", ["192.0.2.4"])

    def test_invalid_patterns_rollback_entire_batch(self):
        for pattern in ("**.removed.test", "([a-z).bad.test", "(?=a).bad.test", r"((a)\1).bad.test",
                        "prefix(a).bad.test", "(a)suffix.bad.test", "(a{1000000000}).bad.test"):
            result = self.server.graphql("mutation($r:[RecordInput!]!){upsert(records:$r)}", {
                "r":[record("atomic.regex.test", "A", "192.0.2.1"), record(pattern, "A", "192.0.2.2")]})
            self.assertIn("errors", result.json(), pattern)
            self.assertEqual(self.query("atomic.regex.test").rcode(), dns.rcode.NXDOMAIN)
