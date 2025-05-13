# ADR-001: Tenancy model

- **Status:** accepted
- **Deciders:** project owner

## Context

Amazon Cognito supports four multitenancy patterns: a user pool per tenant, an
app client per tenant, a group per tenant, and a custom scope per tenant. tenantgate
needs tenant-aware user sign-in (authorization code + PKCE), machine-to-machine
access per tenant, a single user being able to belong to several tenants, and a
path to multi-Region resilience that doesn't multiply operational work by the
number of tenants.

## Options

| Option | For | Against |
|---|---|---|
| Pool per tenant | Strongest isolation; per-tenant password policy, MFA, branding | Heavy automation; users sign up per tenant; per-pool quotas; any cross-Region setup multiplied by the number of pools |
| **App client per tenant** | One user profile across tenants; per-tenant callback URLs and IdPs; cheap to create | Clients share the pool's session cookie, so isolation must be enforced in code |
| Group per tenant | Natural fit for identity-pool role mapping | Group claims are coarse; no per-tenant OAuth configuration |
| **Custom scope per tenant** | Tenant-scoped M2M access with plain client credentials | Scopes alone don't carry the tenant into user tokens |

## Decision

A **shared user pool**, an **app client per tenant** for user sign-in, and
**tenant-scoped custom scopes** (`api/tenant.<id>.read|write`) for M2M clients.

Tenant identity is carried as `tenant_id` / `tenant_role` claims injected by the
pre-token-generation trigger (V3 event), so resource servers don't have to infer
it from the client.

## Consequences

- **The app client alone does not isolate tenants.** The managed-login session
  cookie authenticates a user to every app client in the pool for an hour
  (not configurable), and the pre-authentication trigger does not run on cookie
  sessions. Therefore:
  - pre-token-generation re-checks membership on every issuance and fails closed;
  - `authlib_mt` re-checks that the token's `client_id` still maps to the
    `tenant_id` claim and that the tenant is active.
- The tenant registry (DynamoDB) becomes part of the sign-in path; triggers must
  be fast and read only the local replica.
- The resource server's scope list grows by two scopes per tenant with M2M
  clients. It is owned by the control plane, not by CloudFormation.
- A "pool per tenant" premium mode remains possible later; see the plan's
  optional stretch goals.
