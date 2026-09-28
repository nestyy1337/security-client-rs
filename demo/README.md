# kibana-rs workbench

A small Axum application that drives the `kibana-rs` crate from a browser. It is a workspace member with `publish = false`; nothing here ships in the published crate. Run the commands below from the repository root.

## Try the running workbench

On Szymon's Tailscale network: **http://homebox:8787**. The IP fallback is http://100.115.129.28:8787.

The workbench runs on homebox against a dedicated Elasticsearch/Kibana 9.5.4 stack. It can create and edit query detection rules, enable/disable them, manage security cases and notes, create agent policies, browse/install integrations, and assign integrations to policies. Changes are real, confined to this demonstration deployment. The initial rules and cases are labelled demonstration resources.

The app uses a Kibana user restricted to the `kibana-rs` space. Backend credentials never reach the browser. Network access is controlled by the existing tailnet policy; the demo has no separate browser login. It binds only to the host's Tailscale IP. Elasticsearch and Kibana themselves bind only to loopback on ports 19200 and 15601.

There are no enrolled agents or production events. Fleet Server provisioning, agent enrollment, and actual telemetry collection are outside this demonstration. No dashboard authoring APIs were implemented.

## Run your own isolated demo

Requirements: Nix with flakes, Docker Compose, and a user systemd manager. Rootless Docker is detected. These scripts create only the `kibana-rs-demo` Compose project and `kibana-rs-demo.service`. Expect several GiB of memory and image storage.

```sh
nix develop -c bash deploy/start-stack.sh
KIBANA_RS_BIND="$(tailscale ip -4):8787" nix develop -c bash deploy/start-demo.sh
```

Omit `KIBANA_RS_BIND` to bind the workbench to `127.0.0.1:8787`. Do not bind this demonstration app to a public interface. The Tailscale deployment relies on the tailnet's existing access rules.

The scripts generate credentials under `~/.local/state/kibana-rs` with restricted file permissions. `KIBANA_RS_STATE_DIR` can override this directory. State is outside the checkout. The dedicated stack uses Basic licensing, keeps Elasticsearch data in a named Docker volume, and restarts its containers automatically. A user systemd service runs a separate copy of the release binary and restarts it after failure. Service installation uses the user's data directory rather than modifying a shared dotfiles checkout.

For the user service to start before login and survive logout, enable lingering with `loginctl enable-linger "$(id -un)"`. This is enabled on homebox. Reboot recovery has not been tested.

Package installation requires access to Elastic's package registry. The browser assignment form uses a package's default inputs. Packages requiring additional variables must be configured through the library or Kibana. Installing a package can install its bundled dashboard assets, even though this client provides no dashboard authoring API.

To stop the app, run `systemctl --user stop kibana-rs-demo`. To stop the dedicated containers without deleting data, use Docker Compose with `deploy/compose.yaml` and the generated `stack.env`. The scripts do not alter Tailscale policy or the existing T3 Serve configuration.

## Browser checks

These checks use the real workbench and create/delete their own test resources:

```sh
KIBANA_RS_DEMO_URL=http://homebox:8787 \
CHROME_BIN=/path/to/chrome \
KIBANA_RS_SCREENSHOTS=/tmp/kibana-rs-screenshots \
nix develop -c uv run --with playwright python -u tests/browser.py
```
