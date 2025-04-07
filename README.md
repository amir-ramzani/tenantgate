# tenantgate

A multitenant OAuth 2.0 / OIDC service on Amazon Cognito, written in Python.

Work in progress. The plan:

- **Tenants** are onboarded through a control-plane API; each gets its own app
  client (authorization code + PKCE).
- **Tenant-aware sign-in:** Cognito triggers enforce membership and add
  `tenant_id` / `tenant_role` claims to tokens.
- **M2M:** per-tenant confidential clients with tenant-scoped scopes.
- **`authlib_mt`:** a reusable library that validates tokens and enforces tenant
  isolation in resource servers.
- Infrastructure as code (AWS CDK, Python), deployed from CI.

## Develop

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --group dev
uv run pytest
uv run ruff check . && uv run mypy
pre-commit install
```
