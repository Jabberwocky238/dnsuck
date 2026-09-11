"""Explicit listener flags and independent encrypted listener startup."""
import asyncio
import os
import signal
import subprocess
import time
import unittest

import dns.asyncquery
import dns.message
import dns.query

from support import Server, ROOT, available_port


class ConfigTests(unittest.TestCase):
    def test_missing_and_mismatched_certificates(self):
        binary = os.environ.get("DNS_TEST_BINARY", str(ROOT / "target/debug/dnsuck"))
        for proto in ("doh", "dot", "doq"):
            for args in ([f"--{proto}", "127.0.0.1:8853"], [f"--{proto}", "127.0.0.1:8853", f"--{proto}-cert", "cert.pem"],
                         [f"--{proto}-cert", "cert.pem", f"--{proto}-key", "key.pem"]):
                result = subprocess.run([binary, *args], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
        result = subprocess.run([binary, "--help"], capture_output=True, text=True)
        self.assertNotIn("[env:", result.stdout)
        self.assertNotIn("--https-listen-addr", result.stdout)

    def test_listener_requires_address_and_port(self):
        binary = os.environ.get("DNS_TEST_BINARY", str(ROOT / "target/debug/dnsuck"))
        for proto in ("dns", "doh", "dot", "doq"):
            for values in ([], ["127.0.0.1"], ["127.0.0.1:invalid"]):
                with self.subTest(protocol=proto, values=values):
                    result = subprocess.run([binary, f"--{proto}", *values], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn(f"--{proto} <ADDRESS:PORT>", result.stderr)

    def test_proxy_flags_conflict_with_tls_credentials(self):
        binary = os.environ.get("DNS_TEST_BINARY", str(ROOT / "target/debug/dnsuck"))
        for proto in ("doh", "dot"):
            for extra in ([f"--{proto}-cert", "cert.pem"], [f"--{proto}-key", "key.pem"]):
                result = subprocess.run([binary, f"--{proto}", "127.0.0.1:853",
                                         f"--{proto}-no-cert", *extra], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_removed_management_flags_and_default_listen(self):
        binary = os.environ.get("DNS_TEST_BINARY", str(ROOT / "target/debug/dnsuck"))
        for args in (["--graphql"], ["--api-token", "removed"]):
            result = subprocess.run([binary, *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)
        result = subprocess.run([binary, "--help"], capture_output=True, text=True)
        self.assertIn("127.0.0.1:3080", result.stdout)
        self.assertNotIn("--graphql", result.stdout)
        self.assertNotIn("--api-token", result.stdout)

    def test_each_listener_independently(self):
        server = Server()
        self.addCleanup(server.close)
        server.stop()
        for proto in ("dns", "doh", "dot", "doq"):
            with self.subTest(protocol=proto):
                port = available_port()
                args = [server.binary, "--listen", "127.0.0.1:0", "--database", str(server.path / "lmdb"),
                        f"--{proto}", f"127.0.0.1:{port}"]
                if proto != "dns":
                    args += [f"--{proto}-cert", str(server.cert), f"--{proto}-key", str(server.path / "key.pem")]
                process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 8
                    while True:
                        self.assertIsNone(process.poll(), process.communicate() if process.poll() is not None else "")
                        try:
                            message = dns.message.make_query("host.secure.test", "A")
                            if proto == "dns":
                                reply = dns.query.udp(message, "127.0.0.1", port=port, timeout=0.3)
                            elif proto == "doh":
                                reply = dns.message.from_wire(server.client.post(
                                    f"https://localhost:{port}/dns-query", content=message.to_wire(),
                                    headers={"content-type": "application/dns-message"}).content)
                            elif proto == "dot":
                                reply = dns.query.tls(message, "127.0.0.1", port=port, timeout=0.3,
                                    verify=str(server.cert), server_hostname="localhost")
                            else:
                                reply = asyncio.run(dns.asyncquery.quic(message, "127.0.0.1", port=port,
                                    timeout=0.3, verify=str(server.cert), server_hostname="localhost"))
                            break
                        except Exception:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.025)
                    self.assertEqual(reply.answer[0][0].address, "192.0.2.10")
                finally:
                    process.send_signal(signal.SIGINT)
                    try:
                        out, err = process.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate()
                        raise
                    self.assertEqual(process.returncode, 0, (out, err))
