#!/usr/bin/env bash
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"
export KIBANA_RS_STATE_DIR=${KIBANA_RS_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/kibana-rs}
state=$KIBANA_RS_STATE_DIR
source "$state/stack.env"

cargo build --locked --release -p kibana-rs-demo
KIBANA_URL=http://127.0.0.1:15601 KIBANA_USERNAME=elastic KIBANA_PASSWORD="$ELASTIC_PASSWORD" \
  target/release/kibana-rs-demo --seed
uv run python deploy/configure-demo.py

mkdir -p "$state/bin"
cp target/release/kibana-rs-demo "$state/bin/kibana-rs-demo.new"
mv "$state/bin/kibana-rs-demo.new" "$state/bin/kibana-rs-demo"
units=${XDG_DATA_HOME:-$HOME/.local/share}/systemd/user
mkdir -p "$units/default.target.wants"
cat > "$units/kibana-rs-demo.service" <<EOF
[Unit]
Description=Kibana RS security workbench
After=network-online.target

[Service]
EnvironmentFile=$state/demo.env
ExecStart=$state/bin/kibana-rs-demo
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
UMask=0077

[Install]
WantedBy=default.target
EOF
ln -sfn ../kibana-rs-demo.service "$units/default.target.wants/kibana-rs-demo.service"
export XDG_RUNTIME_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
export DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}
systemctl --user daemon-reload
systemctl --user restart kibana-rs-demo.service
systemctl --user is-active kibana-rs-demo.service
