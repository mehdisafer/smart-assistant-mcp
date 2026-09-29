# Changelog

## v0.1.0 — Public baseline

Initial public release of Smart Assistant MCP.

### Runtime

- 37 governed MCP tools exposed through one Windows-first endpoint.
- Project-scoped filesystem read/list/search/write.
- Durable search sessions with persisted results and cancellation.
- Durable execution broker with idempotency, persisted stdout/stderr, and reconnect-safe reads.
- Windows process, service, port, scheduled-task, and managed-daemon operations.
- Local Wiki/FTS context plane and runtime-generated capability documentation.
- Resource governor with bounded execution and backend admission.

### Developer context

- Optional Serena integration.
- Optional CodeGraph integration.
- Optional Agent Memory integration.
- Optional Desktop Commander compatibility backend.
- Explicit backend tool allowlists and project binding.

### Security and publication

- Loopback-only default configuration.
- Exact project grants and separate mutation allowlists.
- Relative-path enforcement, secret-path denial, and reparse-point protection.
- Optimistic SHA-256 file writes.
- Absolute executable requirement for native command execution.
- Public-history and secret scans completed before release.
- Apache License 2.0.
