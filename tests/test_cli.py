import json
import os
import subprocess
import unittest
from support import Server


@unittest.skipUnless(os.environ.get("DNS_TEST_CLI"), "run scripts/test.sh to build and test dnsuck")
class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from support import ROOT
        cls.server = Server(mmdb=ROOT / "tests/data/country.mmdb")
        cls.addClassCleanup(cls.server.close)
        cls.binary = os.environ["DNS_TEST_CLI"]

    def cli(self, *args, ca=True):
        options = ["--endpoint", self.server.graphql_url + "/graphql"]
        if ca:
            options.extend(["--ca-cert", str(self.server.cert)])
        return subprocess.run([self.binary, *options, *args], text=True, capture_output=True, timeout=15)

    def test_clap_help_and_validation(self):
        result = self.cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("<COMMAND>", result.stdout)
        self.assertIn("<DOMAIN> <RECORD_TYPE>", self.cli("get", "--help").stdout)
        self.assertIn("<DOMAIN> <RECORD_TYPE> <VALUE>", self.cli("set", "--help").stdout)
        for args in [("get", "cli.test"), ("set", "cli.test", "A"),
                     ("get", "cli.test", "A", "extra"), ("delete", "cli.test", "A"),
                     ("set", "cli.test", "A", "192.0.2.1", "--ttl", "invalid")]:
            with self.subTest(args=args):
                self.assertEqual(self.cli(*args).returncode, 2)

    def test_graphql_get_set(self):
        for kind, value, expected in [
            ("a", "192.0.2.17", "192.0.2.17"),
            ("AAAA", "2001:db8::17", "2001:db8::17"),
            ("TXT", '\"hello world\"', "hello world"),
            ("MX", "10 mail.test.", "10 mail.test."),
        ]:
            with self.subTest(kind=kind):
                result = self.cli("set", "cli.test", kind, value, "--ttl", "90")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["upsert"], 1)
                result = self.cli("get", "CLI.TEST.", kind)
                self.assertEqual(result.returncode, 0, result.stderr)
                records = json.loads(result.stdout)["records"]
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0]["data"], expected)
                self.assertEqual(records[0]["ttl"], 90)
        result = self.cli("set", "cli.test", "A", "192.0.2.18")
        self.assertEqual(result.returncode, 0, result.stderr)
        records = json.loads(self.cli("get", "cli.test", "A").stdout)["records"]
        self.assertEqual(records[0]["data"], "192.0.2.18")
        self.assertEqual(records[0]["ttl"], 300)
        self.assertEqual(len(json.loads(self.cli("get", "cli.test", "AAAA").stdout)["records"]), 1)
        self.assertEqual(json.loads(self.cli("get", "missing.test", "A").stdout)["records"], [])
        result = self.cli("set", "raw.test", "TYPE65280", "3q2+7w==", "--raw")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(self.cli("get", "raw.test", "TYPE65280").stdout)["records"]), 1)

    def test_graphql_failures_return_nonzero(self):
        self.assertEqual(self.cli("get", "cli.test", "A", "--token", "removed").returncode, 2)
        self.assertEqual(self.cli("get", "cli.test", "A", ca=False).returncode, 0)
        self.assertNotEqual(self.cli("get", "cli.test", "INVALID").returncode, 0)
        self.assertNotEqual(self.cli("set", "cli.test", "A", "invalid").returncode, 0)
        self.assertNotEqual(self.cli("get", "cli.test", "A", "--endpoint", "http://localhost/graphql").returncode, 0)

    def test_batch_order_and_csv_values(self):
        import csv
        import io
        item = io.StringIO()
        csv.writer(item, lineterminator="").writerow(["set", "batch.test", "TXT", '"hello, world"'])
        result = self.cli("batch",
            "--item", "get,batch.test,A",
            "--item", "set,batch.test,A,192.0.2.40",
            "--item", "get,batch.test,A",
            "--item", item.getvalue(),
            "--item", "get,batch.test,TXT")
        self.assertEqual(result.returncode, 0, result.stderr)
        results = json.loads(result.stdout)
        self.assertEqual(len(results), 5)
        self.assertEqual(results[0], {"records": []})
        self.assertEqual(results[1], {"upsert": 1})
        self.assertEqual(results[2]["records"][0]["data"], "192.0.2.40")
        self.assertEqual(results[4]["records"][0]["data"], "hello, world")

    def test_batch_validation_and_stop_on_error(self):
        self.assertEqual(self.cli("batch").returncode, 2)
        for item in ["", "get,onlydomain", "get,,A", "set,x.test,A", "get,x.test,A,extra", "delete,x.test,A"]:
            with self.subTest(item=item):
                result = self.cli("batch", "--item", "set,notwritten.test,A,192.0.2.1", "--item", item)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("invalid batch item 2", result.stderr)
                self.assertEqual(json.loads(self.cli("get", "notwritten.test", "A").stdout)["records"], [])
        result = self.cli("batch", "--item", "set,partial.test,A,192.0.2.2",
            "--item", "set,bad.test,A,invalid", "--item", "set,unreached.test,A,192.0.2.3")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("batch item 2 failed", result.stderr)
        self.assertEqual(json.loads(self.cli("get", "partial.test", "A").stdout)["records"][0]["data"], "192.0.2.2")
        self.assertEqual(json.loads(self.cli("get", "unreached.test", "A").stdout)["records"], [])

    def test_delete_single_and_batch(self):
        self.assertEqual(self.cli("set", "delete.test", "A", "192.0.2.3").returncode, 0)
        self.assertEqual(self.cli("set", "delete.test", "AAAA", "2001:db8::3").returncode, 0)
        result = self.cli("del", "delete.test", "A")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"delete": 1})
        self.assertEqual(json.loads(self.cli("get", "delete.test", "A").stdout)["records"], [])
        self.assertEqual(len(json.loads(self.cli("get", "delete.test", "AAAA").stdout)["records"]), 1)
        self.assertEqual(json.loads(self.cli("del", "delete.test", "A").stdout), {"delete": 0})
        result = self.cli("batch", "--item", "del,delete.test,AAAA", "--item", "get,delete.test,AAAA")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [{"delete": 1}, {"records": []}])
        self.assertEqual(self.cli("del", "delete.test").returncode, 2)
        self.assertEqual(self.cli("del", "delete.test", "A", "extra", "extra").returncode, 2)

    def test_add_appends_and_put_replaces(self):
        for kind, first, second in [("A", "192.0.2.1", "192.0.2.2"),
                                    ("AAAA", "2001:db8::1", "2001:db8::2"),
                                    ("TXT", '"one"', '"two"'),
                                    ("MX", "10 mail1.test.", "20 mail2.test.")]:
            with self.subTest(kind=kind):
                name = f"append-{kind.lower()}.test"
                self.assertEqual(self.cli("put", name, kind, first).returncode, 0)
                result = self.cli("add", name, kind, second)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {"add": 1})
                self.assertEqual(len(json.loads(self.cli("get", name, kind).stdout)["records"]), 2)
                result = self.cli("add", name, kind, first)
                self.assertEqual(json.loads(result.stdout), {"add": 0})
                self.assertEqual(self.cli("put", name, kind, second).returncode, 0)
                self.assertEqual(len(json.loads(self.cli("get", name, kind).stdout)["records"]), 1)
        self.assertEqual(self.cli("put", "ttl-append.test", "A", "192.0.2.1", "--ttl", "60").returncode, 0)
        self.assertNotEqual(self.cli("add", "ttl-append.test", "A", "192.0.2.2").returncode, 0)
        self.assertEqual(self.cli("add", "ttl-append.test", "A", "192.0.2.2", "--ttl", "60").returncode, 0)
        result = self.cli("batch", "--item", "put,append-batch.test,A,192.0.2.1",
            "--item", "add,append-batch.test,A,192.0.2.2", "--item", "get,append-batch.test,A",
            "--item", "put,append-batch.test,A,192.0.2.3", "--item", "get,append-batch.test,A")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = json.loads(result.stdout)
        self.assertEqual(len(result[2]["records"]), 2)
        self.assertEqual(len(result[4]["records"]), 1)

    def test_ordering_mode_cli_and_batch(self):
        for mode in ("lb", "geo", "random"):
            name = f"mode-{mode}.test"
            result = self.cli("put", name, "A", "192.0.2.1", "--mode", mode)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.cli("add", name, "A", "192.0.2.2").returncode, 0)
            records = json.loads(self.cli("get", name, "A").stdout)["records"]
            self.assertEqual(len(records), 2)
            self.assertTrue(all(record["mode"] == mode.upper() for record in records))
        self.assertEqual(self.cli("put", "mode.test", "A", "192.0.2.1", "--mode", "round").returncode, 2)
        result = self.cli("batch", "--item", "put,mode-batch.test,A,192.0.2.1,lb",
            "--item", "add,mode-batch.test,A,192.0.2.2", "--item", "get,mode-batch.test,A")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)[2]["records"][0]["mode"], "LB")

    def test_overlapping_crud_and_delete_one_value(self):
        import dns.message
        import dns.query
        name = "crud-overlap.test"
        self.assertEqual(self.cli("add", name, "A", "192.0.2.10", "--mode", "lb").returncode, 0)
        self.assertEqual(self.cli("add", name, "A", "192.0.2.20").returncode, 0)
        self.assertEqual(self.cli("add", name, "TXT", '"keep"').returncode, 0)
        records = json.loads(self.cli("get", name, "A").stdout)["records"]
        self.assertEqual({r["data"] for r in records}, {"192.0.2.10", "192.0.2.20"})
        self.assertEqual(len(records), 2)
        result = self.cli("del", name, "A", "192.0.2.10")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"delete": 1})
        records = json.loads(self.cli("get", name, "A").stdout)["records"]
        self.assertEqual([r["data"] for r in records], ["192.0.2.20"])
        self.assertEqual(records[0]["mode"], "LB")
        self.assertEqual(json.loads(self.cli("del", name, "A", "192.0.2.10").stdout), {"delete": 0})
        reply = dns.query.udp(dns.message.make_query(name, "A"), "127.0.0.1", port=self.server.port, timeout=3)
        self.assertEqual([r.address for r in reply.answer[0]], ["192.0.2.20"])
        self.assertEqual(len(json.loads(self.cli("get", name, "TXT").stdout)["records"]), 1)
        self.assertEqual(self.cli("put", name, "A", "192.0.2.30").returncode, 0)
        self.assertEqual(json.loads(self.cli("get", name, "A").stdout)["records"][0]["data"], "192.0.2.30")
        result = self.cli("batch", "--item", "add,crud-overlap.test,A,192.0.2.40",
            "--item", "get,crud-overlap.test,A", "--item", "del,crud-overlap.test,A,192.0.2.30",
            "--item", "get,crud-overlap.test,A")
        self.assertEqual(result.returncode, 0, result.stderr)
        results = json.loads(result.stdout)
        self.assertEqual(len(results[1]["records"]), 2)
        self.assertEqual(results[2], {"delete": 1})
        self.assertEqual([r["data"] for r in results[3]["records"]], ["192.0.2.40"])
        self.assertEqual(self.cli("del", name, "A").returncode, 0)
        self.assertEqual(json.loads(self.cli("get", name, "A").stdout)["records"], [])

    def test_embedded_build_information(self):
        import datetime
        help_text = self.cli("--help").stdout
        self.assertIn("Version: ", help_text)
        self.assertIn("Commit: ", help_text)
        stamp = next(line.removeprefix("Built: ") for line in help_text.splitlines() if line.startswith("Built: "))
        self.assertIsNotNone(datetime.datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo)
        self.assertIn("Built: " + stamp, self.cli("--version").stdout)

    def test_delete_one_typed_and_raw_value(self):
        for kind, first, second, raw in [("TXT", '"first value"', '"second value"', False),
                                         ("MX", "10 mail1.test.", "20 mail2.test.", False),
                                         ("TYPE65280", "AQ==", "Ag==", True)]:
            name = f"delete-value-{kind.lower()}.test"
            flags = ["--raw"] if raw else []
            self.assertEqual(self.cli("put", name, kind, first, *flags).returncode, 0)
            self.assertEqual(self.cli("add", name, kind, second, *flags).returncode, 0)
            result = self.cli("del", name, kind, first, *flags)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {"delete": 1})
            self.assertEqual(len(json.loads(self.cli("get", name, kind).stdout)["records"]), 1)
            self.assertEqual(json.loads(self.cli("del", name, kind, first, *flags).stdout), {"delete": 0})
