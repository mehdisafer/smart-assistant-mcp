# Security model

## Safe defaults

The sample configuration:

- binds to `127.0.0.1` only;
- rejects `public_exposure=true`;
- exposes only the local `workspace/` project;
- disables process termination;
- leaves every third-party backend disabled;
- never commits generated bearer identities;
- requires absolute executable paths for native execution.

## Important boundary

Project paths are application-level guardrails. They are not an OS sandbox.

The durable broker launches commands with the rights of the Windows account running the MCP runtime. If that account can read a path, a deliberately executed program may also be able to read it.

For stronger isolation use, in increasing order:

1. a dedicated low-privilege Windows account;
2. ACL-restricted project directories;
3. Windows Sandbox / VM / dedicated dev workstation;
4. a separate remote host with an authenticated ingress.

## Mutation controls

Mutations require both:

- an identity scope such as `workspace:write` or `process:execute`;
- membership in `mutation_projects`.

File writes use optimistic SHA-256 version checks. Process termination uses PID plus process creation time to reduce PID-reuse races. Durable job submission uses caller-supplied idempotency keys.

## Secrets

Never put secrets in `runtime.json` or source files. Keep tokens in the ignored identity registry or an external secret manager.

The public export contains no credentials, private configuration, runtime databases, evidence bundles, backups, or machine-specific paths from the source installation.

## Remote exposure

Do not bind this server directly to a public interface. Put a separately authenticated gateway/tunnel in front of the loopback endpoint and keep local authorization authoritative.
