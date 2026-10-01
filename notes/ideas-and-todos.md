# Ideas and TODOs

Working list, updated 2026-10-01. Ideas here need a reason before they become work.

## This pass

- [x] Explain resource IDs, revision tokens and edit semantics where the names
  alone are not enough.
- [x] Add a few executable doctests for safe edits and checked request fields.
- [x] Give the README a short route into examples and module documentation.
- [x] Sweep the other public modules, stopping when the remaining gaps are
  obvious operations or repetition.

## Later, if needed

- Broaden the contract fixtures when a new workflow or bug exposes a missing
  branch. The current fixtures do not cover every rule type or endpoint.
- Consider a worked example combining action submission, waiting and failure
  inspection. Completion and success are easy to confuse in Fleet.

No blanket requirement to document every method. More text can make the useful
parts harder to find.
