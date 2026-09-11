import unittest
import dns.message
import dns.query
from support import Server
from fixtures import record


class GraphQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server()
        cls.addClassCleanup(cls.server.close)

    def test_unauthenticated_management_and_http_errors(self):
        self.assertEqual(self.server.graphql("{names}").status_code, 200)
        result = self.server.client.post(self.server.graphql_url + "/graphql", headers={"Authorization":"Bearer wrong"}, json={"query":"{names}"})
        self.assertEqual(result.status_code, 200)
        headers = {}
        self.assertEqual(self.server.client.get(self.server.graphql_url + "/graphql", headers=headers).status_code, 405)
        self.assertEqual(self.server.client.post(self.server.graphql_url + "/graphql", headers=headers, content=b"bad").status_code, 415)
        headers["content-type"] = "application/json"
        self.assertEqual(self.server.client.post(self.server.graphql_url + "/graphql", headers=headers, content=b"bad").status_code, 400)
        self.assertEqual(self.server.client.post(self.server.graphql_url + "/graphql", headers=headers, content=b"x" * (1024 * 1024 + 1)).status_code, 413)

    def test_crud_pagination_live_dns_and_persistence(self):
        self.assertEqual(self.server.upsert([record("manage.test.", "A", "192.0.2.42", 60), record("manage.test.", "TXT", '"managed"', 60)]), 2)
        result = self.server.graphql('query($name:String!){records(name:$name){name recordType ttl data}}', {"name":"MANAGE.TEST"}).json()
        self.assertNotIn("errors", result)
        self.assertEqual({r["recordType"] for r in result["data"]["records"]}, {"A", "TXT"})
        page = self.server.graphql('{names(limit:2)}').json()["data"]["names"]
        next_page = self.server.graphql('query($after:String){names(after:$after,limit:2)}', {"after":page[-1]}).json()["data"]["names"]
        self.assertTrue(all(name > page[-1] for name in next_page))
        self.assertEqual(self.server.graphql('{names(prefix:"manage",limit:1)}').json()["data"]["names"], ["manage.test."])
        query = dns.message.make_query("manage.test", "A")
        reply = dns.query.udp(query, "127.0.0.1", port=self.server.port)
        self.assertEqual(reply.answer[0][0].address, "192.0.2.42")
        self.server.stop()
        self.server.start()
        self.assertEqual(self.server.graphql('{records(name:"manage.test",recordType:"TXT"){data}}').json()["data"]["records"][0]["data"], 'managed')
        deleted = self.server.graphql('mutation{delete(name:"manage.test",recordType:"A")}').json()
        self.assertEqual(deleted["data"]["delete"], 1)
        self.assertEqual(self.server.graphql('mutation{delete(name:"manage.test")}').json()["data"]["delete"], 1)
        self.assertEqual(self.server.graphql('{records(name:"manage.test"){name}}').json()["data"]["records"], [])

    def test_invalid_mutation_does_not_write(self):
        result = self.server.graphql('mutation($records:[RecordInput!]!){upsert(records:$records)}', {"records":[record("rollback.test.", "A", "192.0.2.1"), record("bad.test.", "A", "invalid")]}).json()
        self.assertIn("errors", result)
        self.assertEqual(self.server.graphql('{records(name:"rollback.test"){name}}').json()["data"]["records"], [])
        self.assertIn("errors", self.server.graphql('{names(limit:10000)}').json())
        self.assertIn("errors", self.server.graphql('{unknownField}').json())

    def test_routes_are_separate(self):
        response = self.server.client.post(self.server.url + "/graphql",
            json={"query": "{names}"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.server.client.get(self.server.graphql_url + "/dns-query").status_code, 404)

    def test_management_only_without_certificates(self):
        server = Server(management_only=True)
        try:
            self.assertFalse(any("cert" in arg or "key" in arg for arg in server.args))
            response = server.graphql("{names}")
            self.assertEqual(response.status_code, 200)
            self.assertIn("secure.test.", response.json()["data"]["names"])
        finally:
            server.close()
