# ADR-002: Multi-Region design

- **Status:** accepted
- **Deciders:** project owner

## Context

Authentication is on every tenant's critical path. Cognito multi-Region
replication (MRR) replicates users, credentials, app clients (including M2M
secrets) and pool configuration to one secondary Region, which can then sign
users in and issue tokens. It is **primary/secondary**: admin and write APIs
work only in the primary.

## Decision

| Layer | Pattern |
|---|---|
| Identity (Cognito) | Active-passive via MRR; secondary activated after its regional configuration is in place |
| Token validation | Active-active and stateless (JWT + cached JWKS, no per-request Cognito call) |
| Demo/data-plane API | Active-active behind a Route 53 failover record |
| Control plane | Primary-only writes; read-only in the secondary and during failover (`503` + `Retry-After`) |
| Tenant registry | DynamoDB global table, single writer (primary control plane; JIT membership only in the primary) |

Day-one choices that are expensive to retrofit:

1. Essentials feature plan and a **multi-Region KMS customer-managed key**.
2. **Multi-Region issuer** (`IssuerConfiguration = UPDATED`). Changing `iss`
   later breaks every validator, so it is fixed before the first tenant exists
   and pinned in config (`-c token_issuer=…`).
3. **Custom domain with managed login v2** (the classic hosted UI isn't
   supported on replicas).
4. **Email MFA**, not TOTP (TOTP isn't available in the secondary).
5. **No passkeys** in v1 (bound to the relying-party ID).

Failover signal: a synthetic canary in the primary requests an M2M token and
runs `InitiateAuth` every minute. Its `AuthHealthy` metric backs a CloudWatch
alarm, which backs one Route 53 health check. That single health check drives
both the Cognito custom domain's `Routing.Failover` and the `api.*` failover
record, so identity and API fail over together.

## Consequences

- Triggers, WAF, SES, alarms and the system-client list are deployed per Region
  (`regional_stack.py`); triggers never make cross-Region calls.
- In the secondary: no user creation, password reset or profile change; the UI
  reads `/status` and hides those flows.
- Lockout counters are not shared between Regions (accepted; see threat model).
- Federated users need both Regions' `idpresponse` URLs registered and must have
  signed in to the primary at least once.
- Failback is manual (see the DR runbook).
- Open items to verify in the first drill: are primary-issued refresh tokens
  honoured by the secondary; do primary-issued access tokens validate unchanged
  after failover; must trigger functions live in the replica's Region.
