# Workbench

A development-only Axum application that exercises the crate from a browser. It is not published and will be removed before the first release.

Run it against an existing Kibana from the repository root:

```sh
KIBANA_URL=http://127.0.0.1:5601 KIBANA_USERNAME=elastic KIBANA_PASSWORD=... \
  cargo run -p kibana-rs-demo
```

`deploy/` contains scripts that start a dedicated local stack and install the workbench as a user service.
