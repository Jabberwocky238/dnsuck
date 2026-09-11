"""Shared temporary HTTPS/DNS server and certificate fixture."""
import datetime
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import ipaddress

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

ROOT = Path(__file__).resolve().parents[1]
from fixtures import record, write
INITIAL_RECORDS = [
    record("secure.test.", "SOA", "ns.secure.test. hostmaster.secure.test. 1 3600 600 86400 300"),
    record("secure.test.", "NS", "ns.secure.test."),
    record("ns.secure.test.", "A", "192.0.2.53"),
    record("host.secure.test.", "A", "192.0.2.10"),
    record("host.secure.test.", "AAAA", "2001:db8::10"),
    record("alias.secure.test.", "CNAME", "host.secure.test."),
    record("text.secure.test.", "TXT", '"signed text"'),
]


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Server:
    def __init__(self, signed=False, encrypted_dns=False, management_only=False, proxy=False):
        self.temp = tempfile.TemporaryDirectory(prefix="dns-web-test-")
        self.path = Path(self.temp.name)
        self.process = None
        self.client = None
        self.binary = os.environ.get("DNS_TEST_BINARY", str(ROOT / "target/debug/dnsuck"))
        self.port = available_port()
        self.https_port = available_port()
        self.management_port = available_port()
        self.dot_port = available_port()
        self.doq_port = available_port()
        self.signing_key = ec.generate_private_key(ec.SECP256R1())
        key_bytes = self.signing_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        (self.path / "key.pem").write_bytes(key_bytes)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(self.signing_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(self.signing_key, hashes.SHA256()))
        self.cert = self.path / "cert.pem"
        self.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.args = ["--listen", f"127.0.0.1:{self.management_port}", "--database", str(self.path / "lmdb"), "--dns", f"127.0.0.1:{self.port}",
                     "--doh", f"127.0.0.1:{self.https_port}", "--doh-cert", str(self.cert),
                     "--doh-key", str(self.path / "key.pem")]
        if management_only:
            self.args = ["--listen", f"127.0.0.1:{self.management_port}",
                         "--database", str(self.path / "lmdb")]
        if encrypted_dns:
            for proto, port in [("dot", self.dot_port), ("doq", self.doq_port)]:
                self.args.extend([f"--{proto}", f"127.0.0.1:{port}", f"--{proto}-cert", str(self.cert),
                                  f"--{proto}-key", str(self.path / "key.pem")])
        if proxy:
            for proto in ("doh", "dot"):
                if f"--{proto}" in self.args:
                    for flag in (f"--{proto}-cert", f"--{proto}-key"):
                        index = self.args.index(flag)
                        del self.args[index:index + 2]
                    self.args.append(f"--{proto}-no-cert")
        if signed:
            self.args.extend(["--dnssec-zone", "secure.test.", "--dnssec-key-file", str(self.path / "key.pem")])
        write(self.binary, self.args, INITIAL_RECORDS)
        self.url = f"{'http' if proxy else 'https'}://localhost:{self.https_port}"
        self.graphql_url = f"http://127.0.0.1:{self.management_port}"
        self.context = ssl.create_default_context(cafile=str(self.cert))
        self.client = httpx.Client(verify=self.context, http2=True, trust_env=False, timeout=5)
        self.start()

    def run(self, *args):
        result = subprocess.run([self.binary, *self.args, *args], capture_output=True,
                                text=True, timeout=15)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result

    def start(self):
        self.process = subprocess.Popen([self.binary, *self.args], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError(self.process.communicate())
            try:
                result = self.client.get(self.graphql_url + "/")
                if result.status_code == 404:
                    return
            except httpx.HTTPError:
                time.sleep(0.025)
        self.close()
        raise AssertionError("HTTPS server did not start")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            try:
                out, err = self.process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate()
                raise AssertionError("server failed to shut down")
            if self.process.returncode:
                raise AssertionError((out, err))

    def close(self):
        try:
            if self.client:
                self.client.close()
            self.stop()
        finally:
            self.temp.cleanup()

    def graphql(self, query, variables=None):
        return self.client.post(self.graphql_url + "/graphql",
                                json={"query": query, "variables": variables or {}})

    def upsert(self, records):
        result = self.graphql("mutation($records:[RecordInput!]!){upsert(records:$records)}", {"records": records})
        result.raise_for_status()
        payload = result.json()
        if "errors" in payload:
            raise AssertionError(payload)
        return payload["data"]["upsert"]
