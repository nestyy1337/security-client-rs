"""Guard against overstated or silently missing coverage entries."""
import copy
from pathlib import Path
import tempfile
import unittest

from api_coverage import called, canonical, inventory, report, validate, wrappers


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "src").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "src/fleet.rs").write_text('''
impl<'a> Fleet<'a> {
    pub fn agent(&self, id: &str) -> GetAgent<'a> {
        GetAgent(self.0.request(Method::GET, Scope::Space, &["api", "fleet", "agents", id]))
    }
}

impl GetAgent<'_> {
    pub fn with_metrics(self, enabled: bool) -> Self {
        Self(self.0.param("withMetrics", enabled))
    }
}
''')
        (self.root / "tests/fleet.rs").write_text("client\n    .fleet()\n    .agent(\"a\")\n")
        self.spec = {"paths": {"/api/fleet/agents/{agentId}": {
            "get": {"operationId": "get-agent"}
        }}}
        self.metadata = {"version": "9.5.4", "url": "https://example.invalid/kibana.yaml", "sha256": "0" * 64}
        self.rows = [{"wrapper": "fleet.agent", "method": "GET",
                      "path": "/api/fleet/agents/{agentId}", "scope": "Space",
                      "operation_id": "get-agent", "contract": "unreviewed",
                      "notes": "No live agent evidence."}]

    def test_parameter_spelling_matches_but_space_prefix_does_not_disappear(self):
        validate(self.root, inventory(self.spec), self.rows)
        self.assertEqual(canonical("/api/fleet/agents/{id}"), canonical(self.rows[0]["path"]))
        self.assertNotEqual(canonical("/s/{spaceId}/api/fleet/agents/{id}"), canonical(self.rows[0]["path"]))

    def test_missing_wrapper_and_wrong_scope_fail(self):
        with self.assertRaisesRegex(ValueError, "Wrapper inventory differs"):
            validate(self.root, inventory(self.spec), [])
        self.rows[0]["scope"] = "Global"
        with self.assertRaisesRegex(ValueError, "Rust route differs"):
            validate(self.root, inventory(self.spec), self.rows)

    def test_changed_route_and_operation_id_fail(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["method"] = "DELETE"
        with self.assertRaisesRegex(ValueError, "absent from pinned spec"):
            validate(self.root, inventory(self.spec), rows)
        self.rows[0]["operation_id"] = "renamed-operation"
        with self.assertRaisesRegex(ValueError, "Operation ID changed"):
            validate(self.root, inventory(self.spec), self.rows)

    def test_duplicate_upstream_route_is_not_silently_collapsed(self):
        self.spec["paths"]["/api/fleet/agents/{id}"] = {"get": {"operationId": "other-agent"}}
        with self.assertRaisesRegex(ValueError, "Ambiguous upstream route"):
            inventory(self.spec)

    def test_unrecognized_new_wrapper_fails_closed(self):
        with (self.root / "src/fleet.rs").open("a") as source:
            source.write("pub fn new_method<I: IntoIterator<Item = S>>(&self, x: I) -> X<'a> { indirect() }")
        with self.assertRaisesRegex(ValueError, "Review route extraction for fleet.new_method"):
            wrappers(self.root)

    def test_wrappers_need_an_offline_wire_test(self):
        (self.root / "tests/fleet.rs").write_text("// no calls")
        (self.root / "tests/live.rs").write_text("client.fleet().agent(id)")
        with self.assertRaisesRegex(ValueError, "without an offline wire test.*fleet.agent"):
            validate(self.root, inventory(self.spec), self.rows)

    def test_live_column_counts_calls_through_namespace_variables_only(self):
        (self.root / "tests/live.rs").write_text("let fleet = client.fleet();\nfleet.agent(&id).send();")
        self.assertEqual(called(self.root, {"fleet.agent"}, live=True), {"fleet.agent"})
        (self.root / "tests/live.rs").write_text("let other = client.fleet();\nother.agent(&id).send();")
        self.assertEqual(called(self.root, {"fleet.agent"}, live=True), set())
        (self.root / "tests/live.rs").write_text("let fleet = client.fleet();\nfleet.wait_for_agent_policy(&id, p, 1, o);")
        self.rows[0]["wrapper"] = "fleet.get_agent"
        self.assertEqual(called(self.root, {"fleet.get_agent"}, live=True), {"fleet.get_agent"})
        self.rows[0]["wrapper"] = "fleet.agent"
        (self.root / "tests/live.rs").write_text("")
        content = report(self.root, self.metadata, inventory(self.spec), self.rows)
        self.assertIn("| `fleet.agent` | `get-agent` | `GET /api/fleet/agents/{agentId}` | unreviewed | - |", content)


if __name__ == "__main__":
    unittest.main()
