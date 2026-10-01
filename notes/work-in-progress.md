# Work in progress

Working notes, updated 2026-10-01.

The route inventory now has a companion schema check. It compares all 78 named
operations across 9.4.7 and 9.5.4, and checks 15 retained fixtures. That catches
more than route changes, though the fixtures still cover selected workflows.
The details live in [schema drift](../docs/schema-drift.md).

The documentation sweep is done for now. [Agent policies](../src/fleet/agent_policies.rs)
are a useful starting point: the type explains what a policy is, and the edit
examples show both the serialized body and how to apply it. The namespace and
delivery revision now have explanations next to their fields.

The other useful additions explain saved-object IDs versus portable IDs, retained
edit fields, unread response bodies, and why a finished Fleet action can still
need inspection. The package-policy edit docs also had misleading wording about
fetching a simplified response; the required read is the full policy.

Six new executable doctests cover those behaviors without a Kibana deployment.
The existing HTTP workflow examples remain compile-only. These examples check
the Rust interface; the deployment tests remain the evidence for what the server
accepts.

After another pass, the remaining gaps were mostly obvious getters, setters and
route-shaped methods. That is where this sweep stopped. No runtime code changed.
The README now links the worked examples and explains how to build the API docs.

Local checks passed: 102 offline Rust tests, 11 doctests, formatting, Clippy and
rustdoc with warnings denied. Eight doctests execute and three compile only.
The API inventory, pinned schema checks and README/note links also passed.
No live deployment was rerun for this documentation pass.

These notes record where the work stands. Possible next steps belong in
[ideas and TODOs](ideas-and-todos.md).
