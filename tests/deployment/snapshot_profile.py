"""Write a deployment profile for the newest Elastic Stack snapshot, pinned to today's image digests."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
VERSIONS_URL = "https://artifacts-api.elastic.co/v1/versions"
IMAGES = {
    "ES_IMAGE": "docker.elastic.co/elasticsearch/elasticsearch",
    "KIBANA_IMAGE": "docker.elastic.co/kibana/kibana",
    "AGENT_IMAGE": "docker.elastic.co/elastic-agent/elastic-agent",
}


def release(version):
    return tuple(int(part) for part in version.removesuffix("-SNAPSHOT").split("."))


def newest_snapshot(versions):
    snapshots = [version for version in versions if version.endswith("-SNAPSHOT")]
    if not snapshots:
        raise RuntimeError("No snapshot versions published")
    return max(snapshots, key=release)


def newest_profile():
    profiles = [json.loads(path.read_text()) for path in (HERE / "profiles").glob("*.json")]
    return max(profiles, key=lambda profile: release(profile["version"]))


def digest(image, tag):
    return json.loads(subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", f"{image}:{tag}", "--format", "{{json .Manifest.Digest}}"],
        check=True, capture_output=True, text=True).stdout)


def snapshot_profile(version, base, resolve=digest):
    profile = json.loads(json.dumps(base))
    profile["version"] = version
    profile["images"].update({name: f"{image}@{resolve(image, version)}" for name, image in IMAGES.items()})
    return profile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", help="Snapshot version; defaults to the newest published one")
    args = parser.parse_args()
    if args.version is None:
        versions = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--max-time", "60", VERSIONS_URL],
                                  check=True, capture_output=True, text=True).stdout
        args.version = newest_snapshot(json.loads(versions)["versions"])
    profile = snapshot_profile(args.version, newest_profile())
    args.output.write_text(json.dumps(profile, indent=2) + "\n")
    print(json.dumps(profile["images"], indent=2))


if __name__ == "__main__":
    sys.exit(main())
