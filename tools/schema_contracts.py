# /// script
# requires-python = ">=3.11"
# dependencies = ["PyYAML==6.0.3", "openapi-schema-validator==0.9.0", "jsonschema==4.26.0"]
# ///
"""Compare supported OpenAPI contracts and validate retained JSON fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from openapi_schema_validator import OAS30ReadValidator, OAS30WriteValidator
from jsonschema import Draft4Validator
from jsonschema.validators import extend
import yaml

from api_coverage import ROOT, inventory, require, validate

ANNOTATIONS = {"description", "title", "example", "examples", "externalDocs", "summary"}
SCHEMA_MAPS = {"properties", "patternProperties", "definitions", "$defs"}
SCHEMA_VALUES = {"items", "additionalProperties", "additionalItems", "not", "contains", "if", "then", "else"}
SCHEMA_LISTS = {"allOf", "anyOf", "oneOf", "prefixItems"}
SECTIONS = ("parameters", "request", "responses")
# Bundled rule_source discriminator names lack a mapping to the prefixed
# components. Check the actual union alternatives rather than that shortcut.
UNIONS = {key: Draft4Validator.VALIDATORS[key] for key in ("allOf", "anyOf", "oneOf")}
READ_VALIDATOR = extend(OAS30ReadValidator, UNIONS)
WRITE_VALIDATOR = extend(OAS30WriteValidator, UNIONS)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def resolve(spec, reference):
    require(reference.startswith("#/"), f"External schema reference is unsupported: {reference}")
    value = spec
    for token in reference[2:].split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        require(key in value, f"Unresolved schema reference: {reference}")
        value = value[key]
    return value


def dereference(spec, value):
    seen = set()
    while isinstance(value, dict) and "$ref" in value:
        reference = value["$ref"]
        require(reference not in seen, f"Cyclic OpenAPI object reference: {reference}")
        seen.add(reference)
        value = resolve(spec, reference)
    return value


def schema(spec, value, seen=()):
    """Normalize Schema Objects without dropping similarly named properties or defaults."""
    if not isinstance(value, dict):
        return value
    if "$ref" in value:
        reference = value["$ref"]
        if reference in seen:
            return {"$ref": reference}
        target = schema(spec, resolve(spec, reference), (*seen, reference))
        siblings = schema(spec, {k: v for k, v in value.items() if k != "$ref"}, seen)
        return {"allOf": [target, siblings]} if siblings else target
    normalized = {}
    for key, item in value.items():
        if key in ANNOTATIONS or key.startswith("x-"):
            continue
        if key in SCHEMA_MAPS:
            item = {name: schema(spec, child, seen) for name, child in item.items()}
        elif key in SCHEMA_VALUES:
            item = schema(spec, item, seen)
        elif key in SCHEMA_LISTS:
            item = [schema(spec, child, seen) for child in item]
            if key != "prefixItems":
                item = sorted(item, key=encoded)
        elif key in {"required", "enum", "type"} and isinstance(item, list):
            item = sorted(item, key=encoded)
        normalized[key] = item
    return normalized


def parameter(spec, value):
    value = dereference(spec, value)
    result = {k: v for k, v in value.items() if k not in ANNOTATIONS and not k.startswith("x-")}
    if "schema" in result:
        result["schema"] = schema(spec, result["schema"])
    if "content" in result:
        result["content"] = content(spec, result["content"])
    return result


def content(spec, values):
    result = {}
    for media_type, media in values.items():
        item = {"schema": schema(spec, media["schema"])} if "schema" in media else {}
        if "encoding" in media:
            item["encoding"] = {}
            for name, encoding in media["encoding"].items():
                entry = {k: v for k, v in encoding.items() if k != "headers"}
                if "headers" in encoding:
                    entry["headers"] = {k: parameter(spec, v) for k, v in encoding["headers"].items()}
                item["encoding"][name] = entry
        result[media_type] = item
    return result


def contract(spec, row):
    path = spec["paths"][row["path"]]
    operation = path[row["method"].lower()]
    require(operation["operationId"] == row["operation_id"], f"Operation ID changed: {row['wrapper']}")
    parameters = {}
    for value in [*path.get("parameters", []), *operation.get("parameters", [])]:
        value = parameter(spec, value)
        parameters[f"{value['in']}:{value['name']}"] = value
    request = None
    if "requestBody" in operation:
        body = dereference(spec, operation["requestBody"])
        request = {"required": body.get("required", False), "content": content(spec, body.get("content", {}))}
    responses = {}
    for status, response in operation.get("responses", {}).items():
        response = dereference(spec, response)
        responses[str(status)] = {
            "content": content(spec, response.get("content", {})),
            "headers": {k: parameter(spec, v) for k, v in response.get("headers", {}).items()},
        }
    return {"parameters": parameters, "request": request, "responses": responses}


def snapshots(versions, contracts):
    return {metadata["version"]: {
        "sha256": metadata["sha256"],
        "operations": {name: {section: hashlib.sha256(encoded(value[section]).encode()).hexdigest()
                              for section in SECTIONS}
                       for name, value in sorted(contracts[metadata["version"]].items())},
    } for metadata in versions}


def differences(before, after, path=""):
    if type(before) is not type(after):
        return [(path, "changed", before, after)]
    if isinstance(before, dict):
        changes = []
        for key in sorted(before.keys() | after.keys()):
            child = path + "/" + key.replace("~", "~0").replace("/", "~1")
            if key not in before:
                changes.append((child, "added", None, after[key]))
            elif key not in after:
                changes.append((child, "removed", before[key], None))
            else:
                changes.extend(differences(before[key], after[key], child))
        return changes
    if isinstance(before, list) and path.rsplit("/", 1)[-1] in {"required", "enum"}:
        changes = [(f"{path}/{index}", "removed", value, None)
                   for index, value in enumerate(before) if value not in after]
        changes += [(f"{path}/{index}", "added", None, value)
                    for index, value in enumerate(after) if value not in before]
        if changes:
            return changes
    if isinstance(before, list) and len(before) == len(after):
        return [change for index, (left, right) in enumerate(zip(before, after))
                for change in differences(left, right, f"{path}/{index}")]
    return [] if before == after else [(path, "changed", before, after)]


def brief(value):
    text = encoded(value)
    return text if len(text) <= 160 else text[:157] + "..."


def report(versions, contracts, fixtures):
    lines = ["# Schema drift", "", "Generated by `tools/schema_contracts.py`. Do not edit by hand.", "",
             "Parameters, request bodies and all documented responses are compared for every named builder.",
             "Local schema references are expanded. Descriptions, titles, examples and vendor annotations are ignored;",
             "types, properties, required fields, enums, nullable flags, defaults, constraints and media types are retained.",
             "Changes require review; this comparison does not classify them as breaking or certify complete client support.",
             "Long values are abbreviated below; fingerprints cover their complete normalized contracts.", ""]
    for metadata in versions:
        lines.append(f"- [Kibana {metadata['version']}]({metadata['url']}), SHA-256 `{metadata['sha256']}`.")
    baseline = versions[-1]["version"]
    for metadata in versions[:-1]:
        previous = metadata["version"]
        changed = {name: differences(contracts[previous][name], current)
                   for name, current in contracts[baseline].items()
                   if contracts[previous][name] != current}
        lines += ["", f"## {previous} to {baseline}", "",
                  f"{len(changed)} of {len(contracts[baseline])} named operations have schema changes.", "",
                  "| Contract section | Changed operations |", "| --- | ---: |"]
        for section in SECTIONS:
            count = sum(contracts[previous][name][section] != current[section]
                        for name, current in contracts[baseline].items())
            lines.append(f"| {section} | {count} |")
        lines.append("")
        for name, changes in sorted(changed.items()):
            lines += [f"### `{name}`", "", "| Field path | Change | Before | After |",
                      "| --- | --- | --- | --- |"]
            for path, kind, before, after in changes:
                values = [path, kind, brief(before), brief(after)]
                lines.append("| " + " | ".join(v.replace("|", "\\|").replace("\n", " ") for v in values) + " |")
            lines.append("")
    lines += ["## Retained fixtures", "",
              "Synthetic JSON fixtures are shared by the schema validator and Rust request/response tests.",
              "They cover selected workflows, not every endpoint or schema branch.", "",
              "| Fixture | Builder | Versions | Request | Response |",
              "| --- | --- | --- | --- | --- |"]
    for name, fixture in sorted(fixtures.items()):
        lines.append(f"| `{name}` | `{fixture['wrapper']}` | {', '.join(fixture['versions'])} | "
                     f"{'JSON' if 'request' in fixture else '-'} | {fixture.get('response', {}).get('status', '-')} |")
    lines += ["", "## Validation limits", "",
              "Fixture validation checks OpenAPI 3.0 types, nullability, required fields, formats and union alternatives.",
              "It validates the alternatives directly instead of using discriminator shortcuts: the bundled rule-source",
              "discriminator omits the mapping from `internal` to `Security_Detections_API_InternalRuleSource`.",
              "Discriminator metadata is still included in the schema fingerprints and comparison.", ""]
    for name, fixture in sorted(fixtures.items()):
        for issue in fixture.get("schema_issues", []):
            lines.append(f"- `{name}` {issue['direction']} `{issue['path']}`: {issue['reason']} "
                         f"[Upstream schema]({issue['source']}). The exception applies only while multiple alternatives match;")
            lines.append("  a missing match, another error or an obsolete exception fails the check.")
    return "\n".join(lines) + "\n"


def validate_fixtures(specs, rows, fixtures):
    rows = {row["wrapper"]: row for row in rows}
    require(bool(fixtures), "No retained contract fixtures")
    for name, fixture in fixtures.items():
        require(fixture["wrapper"] in rows, f"Unknown fixture builder: {name}")
        require(bool(fixture["versions"]), f"No fixture versions: {name}")
        require(set(fixture["versions"]) <= specs.keys(), f"Unknown fixture version: {name}")
        require("request" in fixture or "response" in fixture, f"Empty fixture: {name}")
        for version in fixture["versions"]:
            spec = specs[version]
            row = rows[fixture["wrapper"]]
            operation = spec["paths"][row["path"]][row["method"].lower()]
            bodies = []
            if "request" in fixture:
                bodies.append(("request", dereference(spec, operation["requestBody"]), fixture["request"], WRITE_VALIDATOR))
            if "response" in fixture:
                response = fixture["response"]
                bodies.append(("response", dereference(spec, operation["responses"][str(response["status"])]), response["body"], READ_VALIDATOR))
            for direction, body, instance, validator_class in bodies:
                media = body.get("content", {}).get("application/json", {})
                require(bool(media.get("schema")), f"No JSON schema: {name} {version} {direction}")
                validator = validator_class(spec, format_checker=validator_class.FORMAT_CHECKER).evolve(schema=media["schema"])
                errors = list(validator.iter_errors(instance))
                for issue in fixture.get("schema_issues", []):
                    require(issue["kind"] == "ambiguous_one_of" and issue["reason"] and issue["source"].startswith("https://"),
                            f"Invalid schema issue record: {name}")
                    require(issue["direction"] in fixture, f"Schema issue has no fixture body: {name}")
                    if issue["direction"] != direction:
                        continue
                    matches = [error for error in errors if error.validator == "oneOf"
                               and "/" + "/".join(str(token).replace("~", "~0").replace("/", "~1")
                                                     for token in error.absolute_path) == issue["path"]
                               and sum(validator.evolve(schema=alternative).is_valid(error.instance)
                                       for alternative in error.validator_value) > 1]
                    require(len(matches) == 1, f"Known schema issue changed: {name} {version} {issue['path']}")
                    errors.remove(matches[0])
                require(not errors, f"Invalid fixture {name} {version} {direction}: "
                        + "; ".join(f"{error.json_path}: {error.message}" for error in errors[:5]))


def load_spec(metadata, path):
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == metadata["sha256"],
            f"Upstream SHA-256 mismatch for {metadata['version']}; review the pin explicitly")
    spec = yaml.load(raw, Loader=yaml.CSafeLoader)
    require(spec.get("openapi") == "3.0.3", "Review the validator before changing the OpenAPI dialect")
    return spec


def check_outputs(outputs, check):
    for path, expected in outputs.items():
        if check:
            require(path.exists() and path.read_text() == expected,
                    f"{path.name} is stale; run schema_contracts.py --update and review schema changes")
        else:
            path.write_text(expected)
            print(f"Wrote {path.relative_to(ROOT)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fetch", action="store_true", help="Download checksum-pinned bundles to temporary storage")
    source.add_argument("--spec-dir", type=Path, help="Directory containing kibana-VERSION.yaml bundles")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="Validate fixtures and committed schema fingerprints/report")
    mode.add_argument("--update", action="store_true", help="Validate fixtures, then regenerate fingerprints/report for review")
    args = parser.parse_args()
    metadata = json.loads((ROOT / "coverage/upstream.json").read_text())
    versions = [*metadata.get("comparisons", []), {k: v for k, v in metadata.items() if k != "comparisons"}]
    names = [value["version"] for value in versions]
    require(len(names) == len(set(names)), "Duplicate schema version pins")
    supported = {json.loads(path.read_text())["version"] for path in (ROOT / "tests/deployment/profiles").glob("*.json")}
    require(set(names) == supported, "Schema pins must cover every supported deployment version")
    rows = json.loads((ROOT / "coverage/operations.json").read_text())
    fixtures = json.loads((ROOT / "tests/fixtures/contracts.json").read_text())
    with tempfile.TemporaryDirectory(prefix="client-schema-spec-") as temporary:
        directory = Path(temporary) if args.fetch else args.spec_dir
        specs = {}
        for pin in versions:
            path = directory / f"kibana-{pin['version']}.yaml"
            if args.fetch:
                subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "120",
                                pin["url"], "--output", str(path)], check=True)
            specs[pin["version"]] = load_spec(pin, path)
            validate(ROOT, inventory(specs[pin["version"]]), rows)
        contracts = {version: {row["wrapper"]: contract(spec, row) for row in rows} for version, spec in specs.items()}
        validate_fixtures(specs, rows, fixtures)
        check_outputs({
            ROOT / "coverage/schema-snapshots.json": json.dumps(snapshots(versions, contracts), indent=2, sort_keys=True) + "\n",
            ROOT / "docs/schema-drift.md": report(versions, contracts, fixtures),
        }, args.check)
    print(f"Schemas checked: {len(rows)} operations across {len(versions)} versions; {len(fixtures)} retained fixtures")


if __name__ == "__main__":
    main()
