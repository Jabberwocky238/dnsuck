import json
import os
import subprocess
import unittest
from support import Server


@unittest.skipUnless(os.environ.get("DNS_TEST_CLI"), "run scripts/test.sh to build and test cmd")
class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server()
        cls.addClassCleanup(cls.server.close)
        cls.binary = os.environ["DNS_TEST_CLI"]

    def cli(self, *args, token=None, ca=True):
        options = ["--endpoint", self.server.graphql_url + "/graphql", "--token", token or self.server.token]
        if ca:
            options.extend(["--ca-cert", str(self.server.cert)])
        return subprocess.run([self.binary, *options, *args], text=True, capture_output=True, timeout=15)

    def test_clap_help_and_validation(self):
        result = self.cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("<COMMAND>", result.stdout)
        self.assertIn("<DOMAIN> <RECORD_TYPE>", self.cli("get", "--help").stdout)
        self.assertIn("<DOMAIN> <RECORD_TYPE> <VALUE>", self.cli("set", "--help").stdout)
        self.assertNotIn(self.server.token, result.stdout)
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

    def test_auth_and_graphql_failures_return_nonzero(self):
        self.assertNotEqual(self.cli("get", "cli.test", "A", token="wrong").returncode, 0)
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
        self.assertEqual(self.cli("del", "delete.test", "A", "extra").returncode, 2)
