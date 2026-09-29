# Developer backend integrations

The backend manager treats developer context tools as external MCP stdio processes. Nothing is auto-discovered and no backend is enabled by default.

Each backend configuration has four important controls:

- `enabled`: explicit activation;
- `command` + `args`: exact executable and launch arguments;
- `allowed_tools`: the only tools the parent MCP will expose;
- memory/startup/call budgets.

## Serena

Use Serena for symbol-aware navigation and LSP diagnostics. The public allowlist is read-oriented:

```text
search_for_pattern
get_symbols_overview
find_symbol
find_referencing_symbols
find_implementations
find_declaration
get_diagnostics_for_file
get_current_config
initial_instructions
```

Keep semantic mutation tools disabled until separate write gates and tests exist.

## CodeGraph

The current public allowlist contains only `codegraph_explore`. The parent runtime overwrites CodeGraph's project path with the already-authorized project root, so callers cannot use backend arguments to escape project scope.

## Agent Memory

The read-oriented allowlist is `memory_recall`, `memory_sessions`, `memory_smart_search` and `memory_audit`. Store memory data outside the Git repository and do not point the backend at browser/session or secret stores.

## Desktop Commander compatibility

Desktop Commander is optional and external. The compatibility adapter exists for richer file/document operations that are not yet native. It must stay scoped to the authorized project and must not enable remote-device behavior through this path.

## Qualification checklist

Before enabling any backend:

1. record or pin its version;
2. verify its license;
3. inspect the tool catalog;
4. reduce `allowed_tools` to the minimum;
5. run a read-only capability probe;
6. test timeout and queue behavior;
7. validate project-scope enforcement.
