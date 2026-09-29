# Publication roadmap

## P0 — Isolated public export

Status: in progress.

- clone current runtime source into a separate directory;
- remove private Mail/Notification integrations;
- remove machine-specific paths and runtime state;
- add safe config/bootstrap;
- add public architecture and security documentation.

Exit gate: source project unchanged; secret/path scan clean.

## P1 — Reproducible local install

- create a clean Python 3.12 virtual environment;
- install from `pyproject.toml`;
- bootstrap a token and workspace;
- start Streamable HTTP endpoint;
- complete MCP handshake and health call.

Exit gate: fresh clone works without any private Smart Assistant directory.

## P2 — Core regression suite

- filesystem read/list/search/write;
- durable search;
- execution start/run/read/cancel/input;
- idempotency and optimistic-write tests;
- governor pressure tests;
- process/service read tests;
- reboot/reconciliation tests where applicable.

Exit gate: CI + local Windows test suite green.

## P3 — Developer context stack

- documented Serena adapter;
- documented CodeGraph adapter;
- documented Agent Memory adapter;
- backend-specific smoke tests;
- versions and tool allowlists validated.

Exit gate: each backend can be enabled independently.

## P4 — Desktop parity layer

- keep Desktop Commander as an optional external dependency;
- document compatibility matrix;
- close remaining PDF/image/filesystem gaps using native implementations where sensible;
- avoid coupling the core runtime to Desktop Commander internals.

Exit gate: public feature matrix is evidence-based.

## P5 — Packaging and GitHub publication

- Apache License 2.0 selected for the core repository;
- add CONTRIBUTING, SECURITY reporting and third-party notices;
- add GitHub Actions for Windows;
- run secret scanners and dependency audit;
- tag `v0.1.0`;
- create the public GitHub repository and push the sanitized history.

Exit gate: public repo contains only reviewed files and no private history.

## P6 — Remote workstation guide

- document authenticated tunnel/gateway patterns;
- threat model remote control;
- add dedicated-service-account deployment;
- publish Windows service and rollback guide.

Exit gate: remote use is documented without weakening the local security model.
