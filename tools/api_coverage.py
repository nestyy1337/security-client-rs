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
    "exceptions.reference",
}
# Modules without endpoints.
NON_ENDPOINT_MODULES = {"error.rs", "lib.rs", "request.rs"}
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
    for source in sorted((root / "src").glob("*.rs")):
        if source.name in NON_ENDPOINT_MODULES:
            continue
        code = source.read_text()
        functions = list(re.finditer(r"pub fn (\w+)\b[^(]*\(\s*&self", code))
        for function in functions:
            name = f"{source.stem}.{function[1]}"
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


def untested(root, names):
    """Named wrappers never called through their namespace in an offline test."""
    code = "\n".join(
        path.read_text() for path in sorted((root / "tests").glob("*.rs")) if path.name not in LIVE_TESTS
    )
    missing = []
    for name in sorted(names):
        namespace, method = name.split(".")
        call = rf"\.{method}\(" if namespace == "client" else rf"\.{namespace}\(\)\s*\.{method}\("
        if not re.search(call, code):
            missing.append(name)
    return missing


def fingerprint(root, files):
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + (root / name).read_bytes() + b"\0")
    return digest.hexdigest()


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


def validate(root, metadata, operations, rows):
    actual = wrappers(root)
    require(len(rows) == len({r["wrapper"] for r in rows}), "Duplicate wrapper entries")
    names = {r["wrapper"] for r in rows}
    require(names == set(actual), f"Wrapper inventory differs: {sorted(names ^ set(actual))}")
    missing_tests = untested(root, names)
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
        if row["evidence"] is not None:
            require(row["evidence"] in metadata["evidence"]["workflows"], "Unknown evidence reference")

    for workflow in metadata["evidence"]["workflows"].values():
        code = (root / workflow["file"]).read_text()
        require(workflow["symbol"] in code, f"Evidence test no longer exists: {workflow}")


def report(root, metadata, operations, rows):
    evidence = metadata["evidence"]
    current = fingerprint(root, evidence["files"]) == evidence["source_sha256"]
    totals = Counter(group(op) for op in operations.values())
    implemented = Counter()
    recorded = Counter()
    for row in rows:
        name = group(operations[(row["method"], canonical(row["path"]))])
        implemented[name] += 1
        recorded[name] += row["evidence"] is not None

    lines = [
        "# API coverage", "",
        "Generated by `tools/api_coverage.py` from the reviewed operation manifest. Do not edit this file by hand.", "",
        f"Baseline: **traditional Kibana {metadata['version']}**, [tagged upstream bundle]({metadata['url']}).",
        f"SHA-256: `{metadata['sha256']}`.", "",
        f"**{len(rows)} of {len(operations)} published method/path operations have named wrappers "
        f"({100 * len(rows) / len(operations):.1f}%).** This measures endpoint breadth, not full contract parity.", "",
        f"| Area | Published operations | Named wrappers | Recorded exercised on {evidence['kibana_version']} | Missing wrappers |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name in ["Detection engine", "Exceptions", "Cases", "Fleet", "Spaces", "Roles", "Status", "Other APIs"]:
        lines.append(f"| {name} | {totals[name]} | {implemented[name]} | {recorded[name]} | {totals[name] - implemented[name]} |")
    lines += [
        f"| **Total** | **{len(operations)}** | **{len(rows)}** | **{sum(recorded.values())}** | **{len(operations) - len(rows)}** |", "",
        "## What these numbers mean", "",
        "- A named wrapper is a method/path mapping. Generic raw requests do not count as coverage.",
        "- Every named wrapper is called by an offline wire-contract test in `tests/`, which asserts its method, path, query and body against a recording mock. The checker fails otherwise. Wire tests check this client's requests, not Kibana's behavior.",
        "- `partial` means a known request or response limitation. `unreviewed` means full contract parity has not been audited. Neither means complete support.",
        f"- The denominator includes {sum(bool(op.get('deprecated')) for op in operations.values())} deprecated operations, documentation placeholders, and {sum('/internal/' in op['path'] for op in operations.values())} explicit internal route. It is the published bundle inventory, not a list of guaranteed stable public contracts.",
        "- Parameter names are normalized for matching. Explicit `/s/{spaceId}` paths remain distinct. Space-routing behavior must be tested separately.",
        "- Detection engine means `/api/detection_engine`; Exceptions means `/api/exception_lists`. Cases, Fleet and Spaces use their corresponding prefixes. Roles includes `/api/security/role`, its children and `/api/security/roles`. Other APIs includes unimplemented security areas as well as dashboards and unrelated areas.", "",
        "## Evidence and compatibility", "",
        f"The {sum(recorded.values())} recorded exercises refer to the {evidence['date']} local run on traditional Kibana {evidence['kibana_version']} with Basic licensing, at source commit `{evidence['source_commit']}`. They are curated from [the verification record](verification.md), not a machine-attested certification run.", "",
        f"Evidence fingerprint: **{'matches current client and test inputs' if current else 'STALE: client or test inputs changed; historical evidence only'}**.", "",
        "The historical run exercised 44 operations through live tests and status through the browser. It used an empty fleet. The newer [deployment suite](../tests/deployment/README.md) verifies real agents and additional workflows on exact 9.5.4 and 9.4.7 profiles. Its CI results are separate from the historical evidence column below. A successful scenario does not verify every parameter, response variant or permission combination.", "",
        "**Release-certified deployment profiles: none.** Passing deployment scenarios do not certify full API contracts or packaged-release/MSRV compatibility. Successful Fleet binary upgrades and cancellation require a future service-installed Agent fixture. No such success is inferred from dry runs, container rejection or wire tests.", "",
        "## Named operation inventory", "",
        "`live-*` and `browser` below refer to the historical workflows, not current CI runs. A dash means no evidence in that historical record. Current deployment scenarios are documented separately above. All rows have a wrapper; the contract column records the separate completeness assessment.", "",
        "| Rust operation | Official operation ID | HTTP route | Contract | Evidence | Limits |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in sorted(rows, key=lambda r: r["wrapper"]):
        notes = row["notes"].replace("|", "\\|")
        lines.append(f"| `{row['wrapper']}` | `{row['operation_id']}` | `{row['method']} {row['path']}` | {row['contract']} | {row['evidence'] or '-'} | {notes} |")
    lines += ["", "## Evidence references", ""]
    for name, workflow in evidence["workflows"].items():
        lines.append(f"- `{name}`: [{workflow['file']}](../{workflow['file']}), `{workflow['symbol']}`.")
    lines += ["", "See [coverage maintenance](../coverage/README.md) for update/check commands and the [deployment-testing proposal](../research/reproducible-deployments.md) for the release matrix design.", ""]
    return "\n".join(lines)


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
    validate(ROOT, metadata, operations, rows)
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
    evidence = metadata["evidence"]
    current = fingerprint(ROOT, evidence["files"]) == evidence["source_sha256"]
    summary = (
        "<!-- BEGIN API COVERAGE -->\n"
        f"Against the pinned traditional **{metadata['version']}** bundle: **{len(rows)}/{len(operations)} named operations** "
        f"({100 * len(rows) / len(operations):.1f}% endpoint breadth), **{sum(r['evidence'] is not None for r in rows)} recorded exercises** "
        f"on {evidence['kibana_version']}, and **no release-certified deployment profiles**. "
        f"Recorded evidence {'matches the current client/test inputs' if current else 'is STALE for the current client/test inputs'}. "
        "Full contract parity remains unaudited.\n"
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
