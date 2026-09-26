"""Run Rust integration scenarios against one owned, disposable deployment."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SCENARIOS = {
    "live": [
        "detection_rules_crud_export_import_and_space_isolation",
        "security_cases_comments_and_version_conflicts",
        "fleet_policy_and_integration_lifecycle",
        "roles_are_global_and_roundtrip_space_privileges",
    ],
    "deployment": [
        "tls_authentication_and_space_permissions",
        "pagination_returns_all_owned_rules",
        "agent_policy_delivery_ingestion_reassignment_and_unenrollment",
    ],
}


def sha256_files(paths):
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def validate_profile(profile):
    if profile["license"] != "basic" or profile["platform"] != "linux/amd64":
        raise ValueError("Only Basic Linux amd64 profiles are implemented")
    if set(profile["images"]) != {"ES_IMAGE", "KIBANA_IMAGE", "AGENT_IMAGE", "EPR_IMAGE", "GATEWAY_IMAGE"}:
        raise ValueError("Profile must lock every container image")
    for image in profile["images"].values():
        if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", image):
            raise ValueError("Every profile image must be pinned by digest")
    if set(profile["packages"]) != {"system", "fleet_server", "elastic_agent"}:
        raise ValueError("Profile must lock every required package")
    for name, version in profile["packages"].items():
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise ValueError("Package versions must be exact releases")
        for suffix in ["zip", "zip.sig"]:
            if not re.fullmatch(r"[0-9a-f]{64}", profile["package_sha256"].get(f"{name}-{version}.{suffix}", "")):
                raise ValueError("Each package and signature needs a checksum")


class Deployment:
    def __init__(self, profile, directory, artifacts):
        self.profile = profile
        self.directory = directory
        self.artifacts = artifacts
        self.project = "krs-test-" + uuid.uuid4().hex[:12]
        self.secret_values = []
        self.environment = dict(os.environ)
        socket = Path(f"/run/user/{os.getuid()}/docker.sock")
        if not self.environment.get("DOCKER_HOST") and socket.exists():
            self.environment["DOCKER_HOST"] = f"unix://{socket}"
        self.password = self.secret()
        self.kibana_password = self.secret()
        self.writer_password = self.secret()
        self.reader_password = self.secret()
        self.environment.update({
            "FIXTURE_DIR": str(directory), "ELASTIC_PASSWORD": self.password,
            **{key: value for key, value in profile["images"].items()},
        })
        self.compose_command = ["docker", "compose", "-p", self.project, "-f", str(HERE / "compose.yaml")]
        self.context = None
        self.report = {"profile": profile, "project": self.project, "tests": [], "status": "failed"}

    def secret(self):
        value = secrets.token_hex(24)
        self.secret_values.append(value)
        return value

    def redact(self, text):
        for value in sorted(self.secret_values, key=len, reverse=True):
            text = text.replace(value, "[redacted]")
        text = re.sub(r'(?i)("(?:api_key|password|service_token|enrollment_token)"\s*:\s*")[^"]+', r'\1[redacted]', text)
        text = re.sub(r'(?i)(Authorization["\s:=]+(?:Basic|Bearer|ApiKey)\s+)[A-Za-z0-9+/=_-]+', r'\1[redacted]', text)
        return text

    def command(self, args, timeout=600, check=True):
        result = subprocess.run(args, cwd=ROOT, env=self.environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"{args[0]} exited {result.returncode}: {self.redact(result.stdout[-12000:])}")
        return result

    def compose(self, *args, **kwargs):
        return self.command(self.compose_command + list(args), **kwargs)

    def api(self, service, path, method="GET", body=None, username="elastic", password=None):
        auth = base64.b64encode(f"{username}:{password or self.password}".encode()).decode()
        if auth not in self.secret_values:
            self.secret_values.append(auth)
        headers = {"kbn-xsrf": "test-fixture", "Content-Type": "application/json"}
        if service != "epr":
            headers["Authorization"] = "Basic " + auth
        url = self.urls[service] + path
        request = urllib.request.Request(url, method=method, headers=headers,
                                         data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=30) as response:
                data = response.read()
                if path.startswith("/health"):
                    return True
                return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"{method} {path}: HTTP {error.code}: {self.redact(error.read().decode()[:3000])}") from None

    def wait(self, description, probe, timeout=240):
        deadline = time.monotonic() + timeout
        last = "not observed"
        while time.monotonic() < deadline:
            try:
                value = probe()
                if value:
                    print(f"Ready: {description}", flush=True)
                    return value
                last = repr(value)
            except (RuntimeError, urllib.error.URLError, TimeoutError, ConnectionError) as error:
                last = str(error)
            time.sleep(2)
        raise RuntimeError(f"Timed out waiting for {description}: {self.redact(last)}")

    def port(self, service, port):
        address = self.compose("port", service, str(port)).stdout.strip()
        return address.rsplit(":", 1)[1]

    def ready_kibana(self):
        status = self.api("kibana", "/api/status")
        version = status.get("version", {}).get("number")
        level = status.get("status", {}).get("overall", {}).get("level")
        if version and version != self.profile["version"]:
            raise RuntimeError(f"Kibana version {version} differs from profile")
        if not version or level != "available":
            raise RuntimeError(f"Kibana not fully authenticated and available: version={version}, level={level}")
        self.api("kibana", "/api/spaces/space")
        return True

    def certificates(self):
        directory = self.directory / "certs"
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        self.command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                      "-subj", "/CN=Disposable test CA", "-addext", "basicConstraints=critical,CA:TRUE",
                      "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                      "-keyout", str(directory / "ca.key"), "-out", str(directory / "ca.crt")])
        self.command(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                      "-keyout", str(directory / "server.key"), "-out", str(directory / "server.csr")])
        (directory / "extensions").write_text("subjectAltName=DNS:localhost,DNS:elasticsearch,DNS:kibana,DNS:fleet-server,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        self.command(["openssl", "x509", "-req", "-days", "2", "-in", str(directory / "server.csr"),
                      "-CA", str(directory / "ca.crt"), "-CAkey", str(directory / "ca.key"), "-CAcreateserial",
                      "-extfile", str(directory / "extensions"), "-out", str(directory / "server.crt")])
        # The private parent directory protects fixture keys on the host; container UID 1000 needs read access.
        for name in ["server.key", "server.crt", "ca.crt"]:
            (directory / name).chmod(0o644)
        self.context = ssl.create_default_context(cafile=str(directory / "ca.crt"))

    def compile_tests(self):
        print("Building and checking expected integration test names", flush=True)
        result = self.command(["cargo", "test", "--locked", "--test", "live", "--test", "deployment", "--no-run", "--message-format=json"], timeout=900)
        binaries = {}
        for line in result.stdout.splitlines():
            try:
                artifact = json.loads(line)
            except json.JSONDecodeError:
                continue
            if artifact.get("reason") == "compiler-artifact" and artifact.get("executable"):
                binaries[artifact["target"]["name"]] = artifact["executable"]
        for binary, expected in SCENARIOS.items():
            listing = self.command([binaries[binary], "--ignored", "--list"]).stdout
            actual = set(re.findall(r"^(.+): test$", listing, flags=re.M))
            if actual != set(expected):
                raise RuntimeError(f"Integration test inventory differs for {binary}: {actual ^ set(expected)}")
        self.binaries = binaries

    def start(self):
        print("Fetching checksum-locked, signed integration packages", flush=True)
        packages = self.directory / "packages"
        packages.mkdir(mode=0o755)
        packages.chmod(0o755)
        for name, version in self.profile["packages"].items():
            for suffix in ["zip", "zip.sig"]:
                filename = f"{name}-{version}.{suffix}"
                path = packages / filename
                self.command(["curl", "--fail", "--silent", "--show-error", "--max-time", "120",
                              f"https://epr.elastic.co/epr/{name}/{filename}", "-o", str(path)])
                if hashlib.sha256(path.read_bytes()).hexdigest() != self.profile["package_sha256"][filename]:
                    raise RuntimeError(f"Package checksum mismatch: {filename}")
                path.chmod(0o644)
        self.certificates()
        config = {
            "server.host": "0.0.0.0", "server.ssl.enabled": True,
            "server.ssl.certificate": "/certs/server.crt", "server.ssl.key": "/certs/server.key",
            "elasticsearch.hosts": ["https://elasticsearch:9200"],
            "elasticsearch.username": "kibana_system", "elasticsearch.password": self.kibana_password,
            "elasticsearch.ssl.certificateAuthorities": ["/certs/ca.crt"],
            "xpack.encryptedSavedObjects.encryptionKey": self.secret(),
            "xpack.security.encryptionKey": self.secret(), "xpack.reporting.encryptionKey": self.secret(),
            "xpack.fleet.registryUrl": "http://registry:8080", "xpack.fleet.isAirGapped": True,
            "telemetry.enabled": False,
        }
        (self.directory / "kibana.yml").write_text(json.dumps(config))
        (self.directory / "kibana.yml").chmod(0o644)
        self.compose("up", "-d", "elasticsearch", "registry", "gateway", timeout=900)
        self.urls = {
            "es": "https://127.0.0.1:" + self.port("gateway", 9200),
            "epr": "http://127.0.0.1:" + self.port("gateway", 8080),
        }
        def healthy():
            health = self.api("es", "/_cluster/health?wait_for_status=yellow&timeout=1s")
            return health.get("status") in {"yellow", "green"} and not health.get("timed_out")
        self.wait("Elasticsearch", healthy)
        version = self.api("es", "/")["version"]["number"]
        license_type = self.api("es", "/_license")["license"]["type"]
        if version != self.profile["version"] or license_type != self.profile["license"]:
            raise RuntimeError(f"Unexpected deployment: Elasticsearch {version}, license {license_type}")
        self.wait("local package registry", lambda: self.api("epr", "/health?ready=true") is not False)
        for name, version in self.profile["packages"].items():
            package = self.api("epr", f"/package/{name}/{version}")
            if package["version"] != version:
                raise RuntimeError(f"Package mismatch: {name}")
        self.api("es", "/_security/user/kibana_system/_password", "POST", {"password": self.kibana_password})
        self.compose("up", "-d", "kibana", timeout=900)
        self.urls["kibana"] = "https://127.0.0.1:" + self.port("gateway", 5601)
        self.wait("Kibana migrations, plugins and authenticated API", self.ready_kibana, timeout=360)
        self.environment.update({
            "KIBANA_URL": self.urls["kibana"], "KIBANA_USERNAME": "elastic", "KIBANA_PASSWORD": self.password,
            "KIBANA_CA_CERT": str(self.directory / "certs/ca.crt"), "ELASTICSEARCH_URL": self.urls["es"],
            "KIBANA_TEST_SYSTEM_VERSION": self.profile["packages"]["system"],
            "KIBANA_TEST_VERSION": self.profile["version"],
        })

    def identities(self):
        self.api("kibana", "/api/spaces/space", "POST", {"id": "fixture", "name": "Disposable fixture"})
        self.api("kibana", "/s/fixture/api/detection_engine/index", "POST")
        for name, base, password in [("fixture_writer", "all", self.writer_password), ("fixture_reader", "read", self.reader_password)]:
            self.api("kibana", f"/api/security/role/{name}", "PUT", {
                "elasticsearch": {"cluster": ["manage_own_api_key"], "indices": [{"names": ["logs-*", ".alerts-security.alerts-*"], "privileges": ["read", "view_index_metadata"]}]},
                "kibana": [{"base": [base], "spaces": ["fixture"]}],
            })
            self.api("es", f"/_security/user/{name}", "PUT", {"password": password, "roles": [name]})
        key = self.api("es", "/_security/api_key", "POST", {"name": "fixture-writer"}, "fixture_writer", self.writer_password)["encoded"]
        self.secret_values.append(key)
        self.environment.update({"KIBANA_TEST_WRITER_PASSWORD": self.writer_password,
                                 "KIBANA_TEST_READER_PASSWORD": self.reader_password, "KIBANA_TEST_API_KEY": key})

    def agents(self):
        self.api("kibana", "/api/fleet/setup", "POST")
        for name, version in self.profile["packages"].items():
            self.api("kibana", f"/api/fleet/epm/packages/{name}/{version}", "POST", {})
        self.api("kibana", "/api/fleet/fleet_server_hosts", "POST", {"id": "fixture-host", "name": "Fixture Fleet", "host_urls": ["https://fleet-server:8220"], "is_default": True})
        outputs = self.api("kibana", "/api/fleet/outputs")["items"]
        output = next(o for o in outputs if o.get("is_default"))
        self.api("kibana", "/api/fleet/outputs/" + output["id"], "PUT", {"name": output["name"], "type": "elasticsearch", "hosts": ["https://elasticsearch:9200"], "config_yaml": 'ssl.certificate_authorities: ["/certs/ca.crt"]'})
        for policy_id, server in [("fixture-server", True), ("fixture-agent", False), ("fixture-agent-target", False)]:
            self.api("kibana", "/api/fleet/agent_policies?sys_monitoring=false", "POST", {
                "id": policy_id, "name": policy_id, "namespace": "fixture", "monitoring_enabled": [], "is_default_fleet_server": server,
            })
        self.api("kibana", "/api/fleet/package_policies?format=simplified", "POST", {
            "name": "fixture-server-package", "namespace": "fixture", "policy_ids": ["fixture-server"],
            "package": {"name": "fleet_server", "version": self.profile["packages"]["fleet_server"]}, "inputs": {},
        })
        token = self.api("es", "/_security/service/elastic/fleet-server/credential/token/fixture", "POST")["token"]["value"]
        self.secret_values.append(token)
        self.environment["FLEET_SERVICE_TOKEN"] = token
        enrollment = self.api("kibana", "/api/fleet/enrollment_api_keys", "POST", {"policy_id": "fixture-agent"})["item"]["api_key"]
        self.secret_values.append(enrollment)
        self.environment["ENROLLMENT_TOKEN"] = enrollment
        directory = self.directory / "logs"
        directory.mkdir(mode=0o755)
        self.marker = "fixture-" + uuid.uuid4().hex
        stamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        (directory / "system.log").write_text(f"{stamp} fixture test[123]: {self.marker}\n")
        (directory / "system.log").chmod(0o644)
        self.compose("up", "-d", "fleet-server", timeout=900)
        server = self.wait("Fleet Server check-in", lambda: next((a for a in self.api("kibana", "/api/fleet/agents")["items"] if a.get("policy_id") == "fixture-server" and a.get("status") == "online"), None), timeout=300)
        self.compose("up", "-d", "agent", timeout=900)
        agent = self.wait("managed Agent check-in", lambda: next((a for a in self.api("kibana", "/api/fleet/agents")["items"] if a.get("policy_id") == "fixture-agent" and a.get("status") == "online"), None), timeout=240)
        for enrolled in [server, agent]:
            if enrolled["local_metadata"]["elastic"]["agent"]["version"] != self.profile["version"]:
                raise RuntimeError("Enrolled Agent version differs from profile")
        self.compose("restart", "agent")
        container = self.compose("ps", "-q", "agent").stdout.strip()
        restarted_at = datetime.fromisoformat(self.command([
            "docker", "inspect", container, "--format", "{{.State.StartedAt}}"
        ]).stdout.strip())
        self.wait("same Agent checking in after restart", lambda: any(
            a["id"] == agent["id"] and a.get("status") == "online" and a.get("last_checkin")
            and datetime.fromisoformat(a["last_checkin"]) > restarted_at
            for a in self.api("kibana", "/api/fleet/agents")["items"]), timeout=180)
        self.report["agent_restart"] = "passed"
        self.environment.update({"KIBANA_TEST_AGENT_ID": agent["id"], "KIBANA_TEST_MARKER": self.marker})

    def scenario(self, binary, name):
        print(f"Running: {name}", flush=True)
        started = time.monotonic()
        result = self.command([self.binaries[binary], name, "--exact", "--ignored", "--nocapture", "--test-threads=1"], timeout=600, check=False)
        output = self.redact(result.stdout)
        passed = (result.returncode == 0 and "1 passed; 0 failed; 0 ignored;" in output
                  and re.search(rf"^test {re.escape(name)} \.\.\. ok$", output, flags=re.M) is not None)
        (self.artifacts / (name + ".log")).write_text(output)
        self.report["tests"].append({"name": name, "binary": binary, "status": "passed" if passed else "failed", "seconds": round(time.monotonic() - started, 3)})
        if not passed:
            raise RuntimeError(f"Scenario failed or did not run: {name}\n{output[-6000:]}")

    def cleanup(self):
        try:
            logs = self.compose("logs", "--no-color", timeout=60, check=False)
            (self.artifacts / "services.log").write_text(self.redact(logs.stdout))
        finally:
            result = self.compose("down", "--volumes", "--remove-orphans", "--timeout", "15", timeout=120, check=False)
            (self.artifacts / "cleanup.log").write_text(self.redact(result.stdout))
            if result.returncode:
                raise RuntimeError("Owned deployment cleanup failed; see cleanup.log")
            for kind in ["container", "volume", "network"]:
                remaining = self.command(["docker", kind, "ls", "-q", "--filter", f"label=com.docker.compose.project={self.project}"] + (["-a"] if kind == "container" else [])).stdout.strip()
                if remaining:
                    raise RuntimeError(f"Owned {kind} resources remain after cleanup")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=[p.stem for p in (HERE / "profiles").glob("*.json")])
    parser.add_argument("--artifacts", type=Path, default=Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "security-client-tests")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("These initial locked profiles require Linux x86_64")
    profile = json.loads((HERE / "profiles" / (args.profile + ".json")).read_text())
    validate_profile(profile)
    os.umask(0o077)
    artifacts = args.artifacts.resolve() / (args.profile + "-" + uuid.uuid4().hex[:12])
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    code = 1
    with tempfile.TemporaryDirectory(prefix="krs-test-") as temporary:
        deployment = Deployment(profile, Path(temporary), artifacts)
        started = time.monotonic()
        deployment.report.update({
            "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
            "fixture_sha256": sha256_files([p for p in HERE.rglob("*") if p.is_file() and "__pycache__" not in p.parts]),
            "client_test_sha256": sha256_files([*ROOT.glob("src/*.rs"), *ROOT.glob("tests/*.rs"), ROOT / "Cargo.toml", ROOT / "Cargo.lock"]),
            "api_snapshot_sha256": json.loads((ROOT / "coverage/upstream.json").read_text())["sha256"],
            "started_at": datetime.now(timezone.utc).isoformat(),
        })
        try:
            deployment.compile_tests()
            deployment.start()
            for name in SCENARIOS["live"]:
                deployment.scenario("live", name)
            deployment.identities()
            for name in SCENARIOS["deployment"][:2]:
                deployment.scenario("deployment", name)
            deployment.agents()
            deployment.scenario("deployment", SCENARIOS["deployment"][-1])
            deployment.report["status"] = "passed"
            code = 0
        except KeyboardInterrupt:
            deployment.report["status"] = "interrupted"
            code = 130
        except Exception as error:
            deployment.report["error"] = deployment.redact(str(error))
            print(deployment.report["error"], file=sys.stderr, flush=True)
        finally:
            try:
                deployment.cleanup()
                deployment.report["cleanup"] = "passed"
            except Exception as error:
                deployment.report["cleanup"] = deployment.redact(str(error))
                deployment.report["status"] = "failed"
                code = 1
            deployment.report["seconds"] = round(time.monotonic() - started, 3)
            ran = {test["name"] for test in deployment.report["tests"]}
            for binary, names in SCENARIOS.items():
                deployment.report["tests"].extend({"name": name, "binary": binary, "status": "not_run"} for name in names if name not in ran)
            (artifacts / "report.json").write_text(json.dumps(deployment.report, indent=2) + "\n")
    print(f"Result: {deployment.report['status']}; {artifacts / 'report.json'}", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
