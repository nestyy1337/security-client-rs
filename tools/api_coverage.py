# /// script
# requires-python = ">=3.11"
# dependencies = ["PyYAML==6.0.3"]
# ///
"""Check named Rust operations against a pinned upstream API inventory."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
# `&self` methods that are not endpoints: client accessors and value helpers.
NON_ENDPOINTS = {
    "client.cases", "client.default_space", "client.exceptions", "client.fleet", "client.request",
    "client.roles", "client.security", "client.space", "client.space_id", "client.spaces", "client.transport",
    "exceptions.edit", "exceptions.reference", "fleet.as_str", "fleet.edit", "fleet.is_finished",
    "fleet.wait_for_action", "fleet.wait_for_agent_policy", "fleet.wait_for_upload",
}
# Helpers that send requests through named builders. A test calling the helper exercises them.
HELPER_CALLS = {
    "fleet.wait_for_action": {"fleet.agent_action_status"},
    "fleet.wait_for_agent_policy": {"fleet.get_agent"},
    "fleet.wait_for_upload": {"fleet.list_agent_uploads"},
}
# Modules without endpoints. A directory module such as `fleet/` is one namespace.
NON_ENDPOINT_MODULES = {"error", "http", "lib", "pagination", "poll", "request"}
# Live suites need a deployment; wire tests must run offline in every CI job.
LIVE_TESTS = {"live.rs", "deployment.rs"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(path):
    # Parameter spelling is not part of routing. Keep explicit space prefixes.
    return re.sub(r"\{[^}]+\}", "{}", path)


def inventory(spec):
    operations = {}
    ids = set()
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if method not in VERBS:
                continue
            key = (method.upper(), canonical(path))
            require(key not in operations, f"Ambiguous upstream route: {key}")
            op_id = operation["operationId"]
            require(op_id not in ids, f"Duplicate upstream operationId: {op_id}")
            ids.add(op_id)
            operations[key] = {**operation, "path": path, "method": method.upper()}
    return operations


def wrappers(root):
    """Recognize the builder convention; fail on unknown shapes.

    Every endpoint is a namespace method taking `&self` whose body builds exactly
    one `.request(Method::X, Scope::Y, &[...])`. Builder setters take `self`.
    """
    result = {}
    pattern = r"\.request\(\s*Method::(\w+),\s*Scope::(\w+),\s*&\[([^\]]+)\]"
    for source in sorted((root / "src").rglob("*.rs")):
        namespace = source.relative_to(root / "src").parts[0].removesuffix(".rs")
        if namespace in NON_ENDPOINT_MODULES:
            continue
        code = source.read_text()
        functions = list(re.finditer(r"pub (?:async )?fn (\w+)\b[^(]*\(\s*&self", code))
        for function in functions:
            name = f"{namespace}.{function[1]}"
            if name in NON_ENDPOINTS:
                continue
            following = re.compile(r"\bfn\s+\w+").search(code, function.end())
            end = following.start() if following else len(code)
            calls = list(re.finditer(pattern, code[function.start():end]))
            require(len(calls) == 1, f"Review route extraction for {name}: expected one direct request")
            method, scope, segments = calls[0].groups()
            path = "/" + "/".join(
                part.strip().strip('"') if part.strip().startswith('"') else "{}"
                for part in segments.split(",") if part.strip()
            )
            require(name not in result, f"Duplicate wrapper: {name}")
            result[name] = (method, path, scope)
    return result


def called(root, names, live):
    """Wrappers called from the offline wire tests, or from the live suites when `live` is set.

    A call is `.namespace().method(` or `namespace.method(` on a variable named after the namespace.
    """
    files = sorted((root / "tests").glob("*.rs"))
    code = "\n".join(path.read_text() for path in files if (path.name in LIVE_TESTS) == live)
    def calls(name):
        namespace, method = name.split(".")
        receiver = r"" if namespace == "client" else rf"(?:\.{namespace}\(\)|\b{namespace})\s*"
        return re.search(rf"{receiver}\.{method}\(", code) is not None

    found = {name for name in names if calls(name)}
    for helper, builders in HELPER_CALLS.items():
        if calls(helper):
            found |= builders & set(names)
    return found


def group(operation):
    path = operation["path"]
    for prefix, name in [
        ("/api/detection_engine", "Detection engine"),
        ("/api/exception_lists", "Exceptions"),
        ("/api/fleet", "Fleet"),
        ("/api/cases", "Cases"),
        ("/api/spaces", "Spaces"),
    ]:
        if path == prefix or path.startswith(prefix + "/"):
            return name
    if path in {"/api/security/role", "/api/security/roles"} or path.startswith("/api/security/role/"):
        return "Roles"
    if path == "/api/status":
        return "Status"
    return "Other APIs"


def validate(root, operations, rows):
    actual = wrappers(root)
    require(len(rows) == len({r["wrapper"] for r in rows}), "Duplicate wrapper entries")
    names = {r["wrapper"] for r in rows}
    require(names == set(actual), f"Wrapper inventory differs: {sorted(names ^ set(actual))}")
    missing_tests = sorted(names - called(root, names, live=False))
    require(not missing_tests, f"Wrappers without an offline wire test: {missing_tests}")
    seen = set()
    for row in rows:
        key = (row["method"], canonical(row["path"]))
        require(key not in seen, f"Duplicate operation mapping: {key}")
        seen.add(key)
        require(key in operations, f"Operation absent from pinned spec: {key}")
        require(operations[key]["operationId"] == row["operation_id"], f"Operation ID changed: {key}")
        expected = (*key, row["scope"])
        require(actual[row["wrapper"]] == expected, f"Rust route differs: {row['wrapper']}")
        require(row["contract"] in {"partial", "unreviewed"}, "Complete contracts require an explicit audit mechanism")
        require(bool(row["notes"]), f"Missing limitations: {row['wrapper']}")
        if evidence := row.get("live_evidence"):
            require(evidence["outcome"] in {"success", "rejection"}, f"Invalid live outcome: {row['wrapper']}")
            file, scenario = evidence["test"].split(":", 1)
            require(file in LIVE_TESTS, f"Not a live suite: {file}")
            source = (root / "tests" / file).read_text()
            require(re.search(rf"\basync fn {re.escape(scenario)}\(", source), f"Missing live scenario: {evidence['test']}")
            require(row["wrapper"] in called(root, names, live=True), f"No live call for evidence: {row['wrapper']}")


AREAS = ["Detection engine", "Exceptions", "Cases", "Fleet", "Spaces", "Roles", "Status", "Other APIs"]


def report(root, metadata, operations, rows):
    live = called(root, {r["wrapper"] for r in rows}, live=True)
    totals = Counter(group(op) for op in operations.values())
    implemented = Counter(group(operations[(r["method"], canonical(r["path"]))]) for r in rows)
    lines = [
        "# API coverage", "",
        "Generated by `tools/api_coverage.py`. Do not edit by hand.", "",
        f"Baseline: the [Kibana {metadata['version']} OpenAPI bundle]({metadata['url']}) (SHA-256 `{metadata['sha256']}`).", "",
        f"{len(rows)} of {len(operations)} published operations have a named builder "
        f"({100 * len(rows) / len(operations):.1f}%). This measures endpoint breadth, not contract completeness.", "",
        "| Area | Published | Named | Missing |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name in AREAS:
        lines.append(f"| {name} | {totals[name]} | {implemented[name]} | {totals[name] - implemented[name]} |")
    lines += [
        f"| **Total** | **{len(operations)}** | **{len(rows)}** | **{len(operations) - len(rows)}** |", "",
        "- Every named builder has an offline test asserting its method, path, query and body.",
        "- **Live** is `success` or `rejection` when a linked scenario's outcome has been reviewed; `called` records call presence only. These labels describe tests, not a fresh passing run.",
        "- **Contract** is `partial` when a known request or response option is not modeled and `unreviewed` when the full contract has not been audited.",
        "- The [supported workflow review](supported-contracts.md) records the checked subsets, version differences and limits. Full schemas are not validated by this inventory check.",
        f"- The published total includes {sum(bool(op.get('deprecated')) for op in operations.values())} deprecated operations and some internal or placeholder routes.", "",
        "| Builder | Operation ID | Route | Contract | Live | Limits |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in sorted(rows, key=lambda r: r["wrapper"]):
        notes = row["notes"].replace("|", "\\|")
        mark = "called" if row["wrapper"] in live else "-"
        if evidence := row.get("live_evidence"):
            file, scenario = evidence["test"].split(":", 1)
            mark = f"[{evidence['outcome']}](../tests/{file} \"{scenario}\")"
        lines.append(f"| `{row['wrapper']}` | `{row['operation_id']}` | `{row['method']} {row['path']}` | {row['contract']} | {mark} | {notes} |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--spec", type=Path, help="Local upstream YAML, checksum verified")
    source.add_argument("--fetch", action="store_true", help="Download the pinned YAML to temporary storage")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Fail if committed report differs")
    mode.add_argument("--missing", action="store_true", help="Print uncovered method/path pairs instead of writing")
    args = parser.parse_args()
    metadata = json.loads((ROOT / "coverage/upstream.json").read_text())
    rows = json.loads((ROOT / "coverage/operations.json").read_text())
    if args.fetch:
        with tempfile.TemporaryDirectory(prefix="client-api-spec-") as directory:
            path = Path(directory) / "spec.yaml"
            subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location", "--max-time", "120", metadata["url"], "--output", str(path)], check=True)
            raw = path.read_bytes()
    else:
        raw = args.spec.read_bytes()

    require(hashlib.sha256(raw).hexdigest() == metadata["sha256"], "Upstream SHA-256 mismatch; review a baseline change explicitly")
    operations = inventory(yaml.safe_load(raw))
    validate(ROOT, operations, rows)
    if args.missing:
        covered = {(r["method"], canonical(r["path"])) for r in rows}
        for key, op in sorted(operations.items()):
            if key not in covered:
                print(f"{op['method']} {op['path']}  [{op['operationId']}]")
        return

    content = report(ROOT, metadata, operations, rows)
    readme = ROOT / "README.md"
    marker = r"<!-- BEGIN API COVERAGE -->.*?<!-- END API COVERAGE -->"
    current_readme = readme.read_text()
    require(len(re.findall(marker, current_readme, flags=re.S)) == 1, "Expected one README coverage block")
    summary = (
        "<!-- BEGIN API COVERAGE -->\n"
        f"{len(rows)} of the {len(operations)} operations in the Kibana {metadata['version']} OpenAPI bundle have named builders. "
        "See the [coverage report](docs/api-coverage.md) for each builder's route and known limits.\n"
        "<!-- END API COVERAGE -->"
    )
    updated_readme = re.sub(marker, lambda _: summary, current_readme, flags=re.S)
    outputs = {ROOT / "docs/api-coverage.md": content, readme: updated_readme}
    if args.check:
        for destination, expected in outputs.items():
            require(destination.exists() and destination.read_text() == expected, f"{destination.name} coverage is stale; regenerate and review the diff")
        print(f"Coverage checked: {len(rows)}/{len(operations)} wrappers; report matches")
    else:
        for destination, expected in outputs.items():
            destination.write_text(expected)
            print(f"Wrote {destination}")


if __name__ == "__main__":
    main()
