#!/usr/bin/env python3
"""Benchmark real UDP queries against a temporary 100,000-record LMDB database."""
import argparse
import json
import os
from pathlib import Path
import platform
import random
import select
import signal
import socket
import struct
import subprocess
import tempfile
import time

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from fixtures import expected_rrsets, write


def exchange_batch(address, packets, window):
    """Time send/receive only; independently decode and validate every reply later."""
    responses = {}
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.connect(address)
        sock.setblocking(False)
        start = time.perf_counter()
        while len(responses) < len(packets):
            while sent < len(packets) and sent - len(responses) < window:
                try:
                    sock.send(packets[sent])
                except BlockingIOError:
                    break
                sent += 1
            ready, _, _ = select.select([sock], [], [], 0.1)
            if not ready:
                if time.perf_counter() - start > 10:
                    raise RuntimeError(f"Timed out: {len(responses)}/{len(packets)} replies; no retries")
                continue
            while True:
                try:
                    packet = sock.recv(65535)
                except BlockingIOError:
                    break
                ident = struct.unpack_from("!H", packet)[0]
                if ident >= sent or ident in responses:
                    raise RuntimeError(f"Unexpected or duplicate DNS ID {ident}")
                responses[ident] = packet
        elapsed = time.perf_counter() - start
    return elapsed, responses


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=100_000)
    parser.add_argument("--queries", type=int, default=10_000)
    parser.add_argument("--seconds", type=float, default=1.0)
    parser.add_argument("--window", type=int, default=128)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/benchmark.json")
    args = parser.parse_args()
    if not 1 <= args.queries <= min(args.records, 65536) or args.window < 1 or args.seconds <= 0:
        parser.error("require 1 <= queries <= min(records, 65536), window > 0, seconds > 0")
    binary = ROOT / "target/release/dnsuckd"
    templates = [(rrset.rdtype, next(iter(rrset))) for rrset in expected_rrsets()]
    rng = random.Random(args.seed)
    samples = rng.sample(range(args.records), args.queries)
    packets = []
    for ident, index in enumerate(samples):
        kind, _ = templates[index % len(templates)]
        query = dns.message.make_query(f"r{index}.bench.test.", kind)
        query.id = ident
        packets.append(query.to_wire())
    with tempfile.TemporaryDirectory(prefix="dns-bench-") as temp:
        import base64
        records = []
        for index in range(args.records):
            kind, record = templates[index % len(templates)]
            records.append({"name":f"r{index}.bench.test.", "recordType":dns.rdatatype.to_text(kind),
                            "ttl":300, "rdataBase64":base64.b64encode(record.to_wire()).decode()})
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        server_args = ["--listen", "127.0.0.1:0", "--database", str(Path(temp) / "lmdb"), "--dns", f"127.0.0.1:{port}"]
        start = time.perf_counter()
        loaded = write(binary, server_args, records)
        load_seconds = time.perf_counter() - start
        if f"Stored {args.records} records" not in loaded.stdout:
            raise RuntimeError(loaded.stdout)
        process = subprocess.Popen([str(binary), *server_args], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise RuntimeError(process.communicate())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError("server startup timed out")
                    time.sleep(0.01)
            # A small independent warmup, with IDs starting at zero on its own socket.
            warmup = []
            for ident in range(min(1000, args.records)):
                index = rng.randrange(args.records)
                kind, _ = templates[index % len(templates)]
                query = dns.message.make_query(f"r{index}.bench.test.", kind)
                query.id = ident
                warmup.append(query.to_wire())
            exchange_batch(("127.0.0.1", port), warmup, args.window)
            elapsed, responses = exchange_batch(("127.0.0.1", port), packets, args.window)
            validation_start = time.perf_counter()
            for ident, index in enumerate(samples):
                reply = dns.message.from_wire(responses[ident])
                kind, expected = templates[index % len(templates)]
                name = f"r{index}.bench.test."
                if (reply.id != ident or reply.rcode() != dns.rcode.NOERROR
                        or not reply.flags & dns.flags.QR or reply.flags & dns.flags.TC
                        or len(reply.question) != 1 or reply.question[0].name.to_text() != name
                        or reply.question[0].rdtype != kind or len(reply.answer) != 1
                        or reply.answer[0].name.to_text() != name
                        or reply.answer[0].rdtype != kind or reply.answer[0].ttl != 300
                        or set(reply.answer[0]) != {expected}):
                    raise RuntimeError(f"Incorrect response for query {ident}: {reply}")
            validation_seconds = time.perf_counter() - validation_start
        finally:
            process.send_signal(signal.SIGINT)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise RuntimeError("server shutdown timed out")
            if stderr.strip():
                print(stderr, file=sys.stderr)
            if process.returncode != 0:
                raise RuntimeError((stdout, stderr))
    wire_seconds = elapsed
    elapsed += validation_seconds
    report = {
        "records": args.records, "queries": args.queries, "unique_random_names": len(set(samples)),
        "record_types": sorted({dns.rdatatype.to_text(kind) for kind, _ in templates}),
        "transport": "UDP loopback", "build": "release", "window": args.window, "seed": args.seed,
        "load_seconds": round(load_seconds, 6), "elapsed_seconds": round(elapsed, 6),
        "wire_seconds": round(wire_seconds, 6),
        "queries_per_second": round(args.queries / elapsed), "verified_responses": len(responses),
        "validation_seconds": round(validation_seconds, 6),
        "threshold_seconds": args.seconds, "passed": elapsed <= args.seconds,
        "warmup_queries": len(warmup), "platform": platform.platform(),
        "cpu": platform.processor(), "cpu_count": os.cpu_count(),
        "timing": "First send through all replies plus independent validation; setup, query encoding and warmup excluded. No response cache or retries.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
