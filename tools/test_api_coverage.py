"""Guard against overstated or silently missing coverage entries."""
import copy
from pathlib import Path
import tempfile
import unittest

from api_coverage import canonical, fingerprint, inventory, validate, wrappers


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "src").mkdir()
        (self.root / "src/fleet.rs").write_text('''
pub async fn agent(&self, id: &str) -> Result<Value> {
    self.0.json(self.0.request(Method::GET, Scope::Space, &["api", "fleet", "agents", id])?).await
}
''')
        self.spec = {"paths": {"/api/fleet/agents/{agentId}": {
            "get": {"operationId": "get-agent"}
        }}}
        self.metadata = {"evidence": {"workflows": {}}}
        self.rows = [{"wrapper": "fleet.agent", "method": "GET",
                      "path": "/api/fleet/agents/{agentId}", "scope": "Space",
                      "operation_id": "get-agent", "contract": "unreviewed",
                      "notes": "No live agent evidence.", "evidence": None}]

    def test_parameter_spelling_matches_but_space_prefix_does_not_disappear(self):
        validate(self.root, self.metadata, inventory(self.spec), self.rows)
        self.assertEqual(canonical("/api/fleet/agents/{id}"), canonical(self.rows[0]["path"]))
        self.assertNotEqual(canonical("/s/{spaceId}/api/fleet/agents/{id}"), canonical(self.rows[0]["path"]))

    def test_missing_wrapper_and_wrong_scope_fail(self):
        with self.assertRaisesRegex(ValueError, "Wrapper inventory differs"):
            validate(self.root, self.metadata, inventory(self.spec), [])
        self.rows[0]["scope"] = "Global"
        with self.assertRaisesRegex(ValueError, "Rust route differs"):
            validate(self.root, self.metadata, inventory(self.spec), self.rows)

    def test_changed_route_and_operation_id_fail(self):
        rows = copy.deepcopy(self.rows)
        rows[0]["method"] = "DELETE"
        with self.assertRaisesRegex(ValueError, "absent from pinned spec"):
            validate(self.root, self.metadata, inventory(self.spec), rows)
        self.rows[0]["operation_id"] = "renamed-operation"
        with self.assertRaisesRegex(ValueError, "Operation ID changed"):
            validate(self.root, self.metadata, inventory(self.spec), self.rows)

    def test_duplicate_upstream_route_is_not_silently_collapsed(self):
        self.spec["paths"]["/api/fleet/agents/{id}"] = {"get": {"operationId": "other-agent"}}
        with self.assertRaisesRegex(ValueError, "Ambiguous upstream route"):
            inventory(self.spec)

    def test_unrecognized_new_wrapper_fails_closed(self):
        with (self.root / "src/fleet.rs").open("a") as source:
            source.write("pub async fn new_method(&self) { indirect_request().await }")
        with self.assertRaisesRegex(ValueError, "Review route extraction for fleet.new_method"):
            wrappers(self.root)

    def test_evidence_inputs_change_when_client_changes(self):
        files = ["src/fleet.rs"]
        before = fingerprint(self.root, files)
        with (self.root / files[0]).open("a") as source:
            source.write("// changed client\n")
        self.assertNotEqual(before, fingerprint(self.root, files))


if __name__ == "__main__":
    unittest.main()
