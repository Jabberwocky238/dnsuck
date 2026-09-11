import asyncio
import unittest

import dns.asyncquery
import dns.message
import dns.quic

from encrypted import EncryptedDNSTests


class DoQTests(EncryptedDNSTests, unittest.TestCase):
    transport = "doq"

    def test_multiple_streams_on_one_connection(self):
        async def run():
            async with dns.quic.AsyncioQuicManager(verify_mode=str(self.server.cert), server_name="localhost") as manager:
                connection = manager.connect("127.0.0.1", self.server.doq_port)
                async def query(index):
                    message = dns.message.make_query("example.test", "A" if index % 2 else "AAAA")
                    return await dns.asyncquery.quic(message, "127.0.0.1", connection=connection, timeout=3)
                return await asyncio.gather(*(query(index) for index in range(12)))
        replies = asyncio.run(run())
        self.assertEqual(len(replies), 12)
        self.assertTrue(all(r.answer and r.id == 0 for r in replies))
