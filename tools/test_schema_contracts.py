"""Exercise schema drift detection independently of route and call inventories."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from schema_contracts import check_outputs, contract, differences, load_spec, schema, snapshots, validate_fixtures


class SchemaTests(unittest.TestCase):
    def setUp(self):
        self.row = {"wrapper": "fleet.fixture", "method": "PUT", "path": "/api/fixture/{id}", "operation_id": "update-fixture"}
        self.spec = {
            "openapi": "3.0.3",
            "paths": {self.row["path"]: {
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "put": {"operationId": "update-fixture", "parameters": [],
                        "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Payload"}}}},
                        "responses": {"200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Response"}}}}}},
            }},
            "components": {"schemas": {
                "Payload": {"type": "object", "required": ["id", "revision"], "additionalProperties": False,
                            "properties": {"id": {"type": "string"}, "revision": {"type": "integer", "nullable": True},
                                           "server_only": {"type": "string", "readOnly": True}}},
                "Response": {"type": "object", "required": ["item"], "properties": {"item": {"$ref": "#/components/schemas/Payload"}}},
            }},
        }
        self.fixture = {"fixture": {"wrapper": self.row["wrapper"], "versions": ["test"],
                                    "request": {"id": "a", "revision": None},
                                    "response": {"status": 200, "body": {"item": {"id": "a", "revision": 2, "server_only": "generated"}}}}}

    def hashes(self, spec):
        metadata = [{"version": "test", "sha256": "pin"}]
        return snapshots(metadata, {"test": {self.row["wrapper"]: contract(spec, self.row)}})

    def validate(self, fixture=None, spec=None):
        validate_fixtures({"test": spec or self.spec}, [self.row], fixture or self.fixture)

    def test_referenced_request_and_response_changes_affect_hashes_without_route_changes(self):
        original = self.hashes(self.spec)
        for field, value in [("type", "number"), ("nullable", False), ("default", 7), ("minimum", 1)]:
            changed = copy.deepcopy(self.spec)
            changed["components"]["schemas"]["Payload"]["properties"]["revision"][field] = value
            actual = self.hashes(changed)["test"]["operations"][self.row["wrapper"]]
            previous = original["test"]["operations"][self.row["wrapper"]]
            self.assertNotEqual(actual["request"], previous["request"])
            self.assertNotEqual(actual["responses"], previous["responses"])
            self.assertEqual(actual["parameters"], previous["parameters"])

    def test_required_fields_enums_wrappers_and_media_types_are_detected(self):
        original = self.hashes(self.spec)
        changes = []
        required = copy.deepcopy(self.spec)
        required["components"]["schemas"]["Payload"]["required"].append("server_only")
        changes.append(required)
        enum = copy.deepcopy(self.spec)
        enum["components"]["schemas"]["Payload"]["properties"]["id"]["enum"] = ["a"]
        changes.append(enum)
        wrapper = copy.deepcopy(self.spec)
        wrapper["components"]["schemas"]["Response"]["properties"] = {"items": {"type": "array"}}
        changes.append(wrapper)
        media = copy.deepcopy(self.spec)
        media["paths"][self.row["path"]]["put"]["requestBody"]["content"]["text/plain"] = {"schema": {"type": "string"}}
        changes.append(media)
        for changed in changes:
            self.assertNotEqual(original, self.hashes(changed))

    def test_documentation_and_set_order_do_not_affect_hashes(self):
        changed = copy.deepcopy(self.spec)
        payload = changed["components"]["schemas"]["Payload"]
        payload.update(description="Reworded prose", title="New title", example={"id": "example"}, **{"x-codegen-name": "new-name"})
        payload["required"].reverse()
        changed["components"]["schemas"]["Unrelated"] = {"type": "string"}
        self.assertEqual(self.hashes(self.spec), self.hashes(changed))
        self.assertEqual(schema({}, {"enum": ["b", "a"]}), schema({}, {"enum": ["a", "b"]}))

    def test_property_and_default_names_are_not_treated_as_documentation(self):
        value = {"type": "object", "properties": {"description": {"type": "string"}, "example": {"type": "integer"}},
                 "default": {"description": "stored value", "x-field": 1}}
        self.assertEqual(schema({}, value), value)

    def test_path_parameters_operation_overrides_and_response_headers_are_checked(self):
        changed = copy.deepcopy(self.spec)
        operation = changed["paths"][self.row["path"]]["put"]
        operation["parameters"] = [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}]
        operation["responses"]["200"]["headers"] = {"x-version": {"schema": {"type": "string"}}}
        result = contract(changed, self.row)
        self.assertEqual(result["parameters"]["path:id"]["schema"]["type"], "integer")
        self.assertIn("x-version", result["responses"]["200"]["headers"])
        self.assertNotEqual(self.hashes(self.spec), self.hashes(changed))

    def test_recursive_references_terminate_and_bad_references_fail(self):
        recursive = {"components": {"schemas": {"Node": {"type": "object", "properties": {"next": {"$ref": "#/components/schemas/Node"}}}}}}
        actual = schema(recursive, {"$ref": "#/components/schemas/Node"})
        self.assertEqual(actual["properties"]["next"], {"$ref": "#/components/schemas/Node"})
        for reference in ["https://example.invalid/schema", "#/components/schemas/Absent"]:
            with self.assertRaises(ValueError):
                schema(recursive, {"$ref": reference})

    def test_fixtures_validate_real_references_nullability_and_read_write_context(self):
        self.validate()
        for body in [{"id": "a"}, {"id": "a", "revision": "2"}, {"id": "a", "revision": 2, "server_only": "forged"}]:
            changed = copy.deepcopy(self.fixture)
            changed["fixture"]["request"] = body
            with self.assertRaisesRegex(ValueError, "Invalid fixture"):
                self.validate(changed)
        changed = copy.deepcopy(self.fixture)
        changed["fixture"]["response"]["body"] = {"items": []}
        with self.assertRaisesRegex(ValueError, "Invalid fixture"):
            self.validate(changed)

    def test_union_constraints_are_enforced_without_discriminator_shortcuts(self):
        changed = copy.deepcopy(self.spec)
        changed["components"]["schemas"]["Payload"] = {
            "discriminator": {"propertyName": "type"}, "oneOf": [
                {"type": "object", "properties": {"type": {"enum": ["internal"]}}, "required": ["type"]},
                {"type": "object", "properties": {"type": {"enum": ["external"]}}, "required": ["type"]},
            ],
        }
        fixture = copy.deepcopy(self.fixture)
        fixture["fixture"]["request"] = {"type": "internal"}
        del fixture["fixture"]["response"]
        self.validate(fixture, changed)
        fixture["fixture"]["request"]["type"] = "unknown"
        with self.assertRaisesRegex(ValueError, "Invalid fixture"):
            self.validate(fixture, changed)

    def test_fixture_formats_and_bounds_are_enforced(self):
        changed = copy.deepcopy(self.spec)
        changed["components"]["schemas"]["Payload"]["properties"]["id"]["format"] = "uuid"
        with self.assertRaisesRegex(ValueError, "Invalid fixture"):
            self.validate(spec=changed)
        changed = copy.deepcopy(self.spec)
        changed["components"]["schemas"]["Payload"]["properties"]["revision"]["maximum"] = 1
        with self.assertRaisesRegex(ValueError, "Invalid fixture"):
            self.validate(spec=changed)

    def test_known_ambiguity_cannot_hide_invalid_values_or_obsolete_exceptions(self):
        changed = copy.deepcopy(self.spec)
        alternatives = [{"type": "array", "items": {"type": "string"}}] * 2
        changed["components"]["schemas"]["Payload"]["properties"]["base"] = {"oneOf": alternatives}
        fixture = copy.deepcopy(self.fixture)
        del fixture["fixture"]["response"]
        fixture["fixture"]["request"]["base"] = ["read"]
        fixture["fixture"]["schema_issues"] = [{"kind": "ambiguous_one_of", "direction": "request", "path": "/base",
                                                   "reason": "Identical upstream alternatives", "source": "https://example.invalid/spec"}]
        self.validate(fixture, changed)
        fixture["fixture"]["request"]["base"] = False
        with self.assertRaisesRegex(ValueError, "Known schema issue changed"):
            self.validate(fixture, changed)
        fixture["fixture"]["request"]["base"] = ["read"]
        alternatives[1] = {"type": "array", "items": {"type": "integer"}}
        with self.assertRaisesRegex(ValueError, "Known schema issue changed"):
            self.validate(fixture, changed)

    def test_pinned_checksums_and_stale_output_fail_without_rewriting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spec.yaml"
            raw = json.dumps(self.spec).encode()
            path.write_bytes(raw)
            metadata = {"version": "test", "sha256": hashlib.sha256(raw).hexdigest()}
            self.assertEqual(load_spec(metadata, path), self.spec)
            path.write_bytes(raw + b" ")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                load_spec(metadata, path)
            path.write_text("old snapshot")
            with self.assertRaisesRegex(ValueError, "is stale"):
                check_outputs({path: "new snapshot"}, check=True)
            self.assertEqual(path.read_text(), "old snapshot")

    def test_diff_reports_property_additions_and_type_changes(self):
        changes = differences({"properties": {"id": {"type": "string"}}},
                              {"properties": {"id": {"type": "integer"}, "a/b": {"nullable": True}}})
        self.assertIn(("/properties/id/type", "changed", "string", "integer"), changes)
        self.assertIn(("/properties/a~1b", "added", None, {"nullable": True}), changes)
        self.assertEqual(differences({"enum": ["a", "b"]}, {"enum": ["a", "c"]}),
                         [("/enum/1", "removed", "b", None), ("/enum/1", "added", None, "c")])


if __name__ == "__main__":
    unittest.main()
