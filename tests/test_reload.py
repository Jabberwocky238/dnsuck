"""Persistent TOML settings and explicit reload of a config-file instance."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time
import unittest

import dns.message
import dns.query
import httpx

from support import ROOT, available_port


class ReloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dns-reload-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.config = self.path / "dns.toml"
        self.binary = os.environ.get("DNS_TEST_BINARY", str(ROOT / "target/debug/dnsuck"))
        # Isolate the per-user control socket from other test runs and real servers.
        self.env = dict(os.environ, TMPDIR=str(self.path))
        self.port = available_port()
        self.management_port = available_port()
        self.settings = {"listen": f"127.0.0.1:{self.management_port}",
                         "dns": f"127.0.0.1:{self.port}", "database": "records"}
        self.process = None
        self.client = httpx.Client(trust_env=False, timeout=3)
        self.addCleanup(self.client.close)
        self.addCleanup(self.stop)
        self.save()

    def save(self):
        self.config.write_text("\n".join(f"{key} = {json.dumps(value)}" for key, value in self.settings.items()) + "\n")

    def run_cli(self, *args):
        return subprocess.run([self.binary, *args], env=self.env, capture_output=True, text=True, timeout=30)

    def start(self, args=None):
        self.process = subprocess.Popen([self.binary, *(args if args is not None else ["-c", str(self.config)])],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail(str(self.process.communicate()))
            try:
                if self.client.get(f"http://127.0.0.1:{self.management_port}/").status_code == 404:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.025)
        self.fail("server startup timed out")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                out, err = self.process.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate()
                raise
            self.assertEqual(self.process.returncode, 0, (out, err))

    def populate(self):
        response = self.client.post(f"http://127.0.0.1:{self.management_port}/graphql", json={"query":
            'mutation{upsert(records:[{name:"reload.test",recordType:"A",ttl:60,data:"192.0.2.42"}])}'})
        self.assertEqual(response.json()["data"]["upsert"], 1)

    def query(self, port=None, tcp=False):
        method = dns.query.tcp if tcp else dns.query.udp
        return method(dns.message.make_query("reload.test", "A"), "127.0.0.1", port=port or self.port, timeout=1)

    def test_file_and_flags_are_mutually_exclusive(self):
        for args in [("--dns", "127.0.0.1:53"), ("--database", "records"),
                     ("--listen", "127.0.0.1:3080"), ("put", "test", "192.0.2.1")]:
            result = self.run_cli("-c", str(self.config), *args)
            self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.run_cli("-c", str(self.config), "--reload").returncode, 0)
        for content in ['unknown = true', 'graphql = true', 'api-token = "removed"', 'listen = [', 'doh = "127.0.0.1:8443"']:
            self.config.write_text(content)
            self.assertNotEqual(self.run_cli("-c", str(self.config)).returncode, 0)

    def test_no_config_is_not_reloadable(self):
        self.start(["--listen", f"127.0.0.1:{self.management_port}",
                    "--database", str(self.path / "records")])
        result = self.run_cli("--reload")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no reloadable server", result.stderr)
        self.assertIsNone(self.process.poll())

    def test_reload_listener_changes_and_persistence(self):
        self.start()
        self.populate()
        self.assertTrue((self.path / "records/data.mdb").exists())
        self.assertEqual(self.query().answer[0][0].address, "192.0.2.42")
        self.settings["dns"] = f"127.0.0.1:{available_port()}"
        dot_port = available_port()
        self.settings.update({"dot": f"127.0.0.1:{dot_port}", "dot-no-cert": True})
        self.save()
        pid = self.process.pid
        result = self.run_cli("--reload")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.process.pid, pid)
        self.assertEqual(self.query(dot_port, tcp=True).answer[0][0].address, "192.0.2.42")
        self.assertEqual(self.query(int(self.settings["dns"].split(":")[-1])).answer[0][0].address, "192.0.2.42")
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.port), timeout=0.3)
        self.settings.pop("dns")
        self.management_port = available_port()
        self.settings["listen"] = f"127.0.0.1:{self.management_port}"
        self.save()
        self.assertEqual(self.run_cli("--reload").returncode, 0)
        url = f"http://127.0.0.1:{self.management_port}/graphql"
        self.assertEqual(self.client.post(url, json={"query":"{names}"}).status_code, 200)
        self.stop()
        self.start()
        self.assertEqual(self.query(dot_port, tcp=True).answer[0][0].address, "192.0.2.42")

    def test_rejected_reload_keeps_previous_settings(self):
        self.start()
        self.populate()
        for extra in [{"unknown": True}, {"database": "another"},
                      {"doh": f"127.0.0.1:{available_port()}", "doh-cert": "missing.pem", "doh-key": "missing.key"}]:
            original = self.settings.copy()
            self.settings.update(extra)
            self.save()
            result = self.run_cli("--reload")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.query().answer[0][0].address, "192.0.2.42")
            self.settings = original
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            self.settings["listen"] = f"127.0.0.1:{occupied.getsockname()[1]}"
            self.save()
            result = self.run_cli("--reload")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("previous configuration restored", result.stderr)
            self.assertEqual(self.query().answer[0][0].address, "192.0.2.42")
        self.settings["listen"] = f"127.0.0.1:{self.management_port}"
        self.save()
        self.assertEqual(self.run_cli("--reload").returncode, 0)
