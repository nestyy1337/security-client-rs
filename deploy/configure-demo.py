"""Provision a space-scoped demo user on the dedicated local stack."""
import base64
import json
import os
from pathlib import Path
import secrets
import urllib.request

state = Path(os.environ["KIBANA_RS_STATE_DIR"])
environment = dict(line.split("=", 1) for line in (state / "stack.env").read_text().splitlines())
authorization = base64.b64encode(("elastic:" + environment["ELASTIC_PASSWORD"]).encode()).decode()
headers = {"Authorization": "Basic " + authorization, "Content-Type": "application/json", "kbn-xsrf": "kibana-rs"}


def put(url, body):
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="PUT")
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status


role = {
    "elasticsearch": {
        "cluster": ["monitor", "manage_own_api_key"],
        "indices": [{"names": ["logs-*", "metrics-*", ".alerts-security.alerts-*", "alerts-*"], "privileges": ["read", "view_index_metadata"]}],
    },
    "kibana": [{"base": ["all"], "spaces": ["kibana-rs"]}],
}
put("http://127.0.0.1:15601/api/security/role/kibana_rs_demo", role)
password = secrets.token_hex(24)
put("http://127.0.0.1:19200/_security/user/kibana_rs_demo", {"password": password, "roles": ["kibana_rs_demo"], "full_name": "Kibana RS demonstration"})
bind = os.environ.get("KIBANA_RS_BIND", "127.0.0.1:8787")
lines = ["KIBANA_URL=http://127.0.0.1:15601", "KIBANA_USERNAME=kibana_rs_demo", "KIBANA_PASSWORD=" + password,
         "KIBANA_SPACE=kibana-rs", "KIBANA_RS_BIND=" + bind, "KIBANA_RS_SCREENSHOTS=" + str(state / "screenshots")]
config = state / "demo.env"
config.write_text("\n".join(lines) + "\n")
config.chmod(0o600)
print("Created a demo user restricted to the kibana-rs space.")
