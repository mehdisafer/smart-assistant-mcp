# Licensing notes

The Smart Assistant MCP core is licensed under the Apache License 2.0. The canonical license text is stored in the repository root as `LICENSE`.

Third-party developer backends are not vendored in this repository. They are started as independent processes when configured.

Verified upstream licensing at the time of this export:

- Model Context Protocol Python SDK v2: MIT.
- Serena: historical 1.x releases remain MIT; Serena application v2+ is GPL-3.0-or-later, while SolidLSP remains MIT.
- CodeGraph 1.5.x: MIT.
- `@agentmemory/mcp` 0.9.x: Apache-2.0.
- Desktop Commander 0.2.x: MIT.

Keeping these projects external avoids copying their source into the Apache-2.0-licensed core. Their own upstream licenses continue to apply independently. Always verify the exact dependency version at release time.
