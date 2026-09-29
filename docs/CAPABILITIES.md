# Capability map

The sanitized public core exposes 37 MCP tools.

## Runtime and capability truth

- `runtime_health`
- `capabilities_status`
- `capability_probe`
- `project_info`
- `documentation_status`
- `operational_metrics`

## Wiki/context plane

- `wiki_search`
- `wiki_read`
- `wiki_refresh`

## Filesystem and durable search

- `filesystem_read`
- `filesystem_list`
- `filesystem_search`
- `filesystem_write`
- `search_start`
- `search_results`
- `search_list`
- `search_stop`

## Process and execution plane

- `process_list`
- `process_inspect`
- `process_terminate`
- `execution_start`
- `execution_run`
- `execution_read`
- `execution_list`
- `execution_cancel`
- `execution_input`

## Developer backends

- `backend_tools`
- `backend_call`

The public design targets Serena, CodeGraph and Agent Memory. Desktop Commander compatibility is retained as an optional adapter, not a mandatory runtime dependency.

## Windows operations

- `service_list`
- `service_status`
- `service_control`
- `port_probe`
- `scheduled_task_status`

## Managed daemons

- `daemon_status`
- `daemon_start`
- `daemon_stop`
- `daemon_restart`

## Deliberately excluded from the public core

Application-specific connectors and delivery channels are out of scope. The repository contains only the generic developer-workstation MCP runtime and its optional developer backends.
