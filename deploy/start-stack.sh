#!/usr/bin/env bash
set -euo pipefail
umask 077

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
state=${KIBANA_RS_STATE_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/kibana-rs}
mkdir -p "$state"
if [[ ! -f "$state/stack.env" ]]; then
  {
    printf 'ELASTIC_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'KIBANA_SYSTEM_PASSWORD=%s\n' "$(openssl rand -hex 24)"
    printf 'ENCRYPTION_KEY=%s\n' "$(openssl rand -hex 32)"
  } > "$state/stack.env"
fi
source "$state/stack.env"

if [[ -z ${DOCKER_HOST:-} && -S /run/user/$(id -u)/docker.sock ]]; then
  export DOCKER_HOST="unix:///run/user/$(id -u)/docker.sock"
fi
compose=(docker compose --env-file "$state/stack.env" -f "$repo/deploy/compose.yaml")
"${compose[@]}" up -d elasticsearch

printf 'user = "elastic:%s"\n' "$ELASTIC_PASSWORD" > "$state/curl.conf"
ready=false
for attempt in {1..90}; do
  if curl -fsS --config "$state/curl.conf" http://127.0.0.1:19200/_cluster/health > /dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if [[ $ready != true ]]; then
  echo 'Elasticsearch did not become ready within 180 seconds.' >&2
  exit 1
fi

printf '{"password":"%s"}\n' "$KIBANA_SYSTEM_PASSWORD" > "$state/kibana-password.json"
curl -fsS --config "$state/curl.conf" -H 'Content-Type: application/json' \
  -X POST --data-binary "@$state/kibana-password.json" \
  http://127.0.0.1:19200/_security/user/kibana_system/_password > /dev/null
"${compose[@]}" up -d kibana

for attempt in {1..120}; do
  if curl -fsS --config "$state/curl.conf" http://127.0.0.1:15601/api/status > "$state/status.json" 2>/dev/null; then
    printf 'Kibana is ready at http://127.0.0.1:15601\nState and credentials: %s\n' "$state"
    exit 0
  fi
  sleep 2
done
echo 'Kibana did not become ready within 240 seconds.' >&2
exit 1
