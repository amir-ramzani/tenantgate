# Threat model (v1)

Scope: tenant isolation and availability of authentication. STRIDE-style, focused
on what is specific to this design.

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| 1 | User of tenant A reuses the managed-login cookie at tenant B's authorize URL | Pre-token-generation re-checks membership on every issuance and fails closed; covered by a unit test and an integration test | None known |
| 2 | Token of tenant A used on tenant B's routes | `authlib_mt` compares path tenant and `X-Tenant-Id` with the `tenant_id` claim; the repository derives keys from the context only | None known |
| 3 | Forged/injected `tenant_id` claim | Claim only trusted after signature check; `client_id` must map to the same tenant in the registry | Compromise of the registry writer |
| 4 | M2M client requests another tenant's scopes | Client only allowed its own scopes; pre-token-gen suppresses foreign scopes; resource server drops them again | None known |
| 5 | Removed member keeps access | Membership deleted, `AdminUserGlobalSignOut` revokes refresh tokens; refresh is denied by pre-token-gen | Access token valid until expiry (≤ 60 min) |
| 6 | Disabled tenant keeps access | Client OAuth flows disabled; triggers and `authlib_mt` check status | Directory cache TTL (30 s) plus access-token lifetime for clients not using `authlib_mt` |
| 7 | Credential stuffing / brute force | WAF rate limiting and managed rule groups on the pool; Cognito lockout | Lockout counters are per Region and not replicated under MRR |
| 8 | JWKS endpoint outage | Last-good keys kept; unknown `kid` refresh is rate limited; outage returns `503` not `401` | Key rotation during a long outage |
| 9 | Forged-`kid` flood forces JWKS refetches | Refresh rate limited to once per 30 s | None known |
| 10 | Control-plane abuse | System-client tokens only; platform-admin group; tenant-admin checks per route; idempotency keys | Compromised admin account |
| 11 | Split-brain writes during failover | Single writer; secondary is read-only; `auth_mode` flag; JIT membership only in the primary | Operator error on failback |
| 12 | Long-lived CI credentials leak | GitHub OIDC role restricted to `main` and named environments; no static keys | Compromised workflow on `main` |
| 13 | Secrets in logs | M2M secrets returned once with `Cache-Control: no-store`; never logged | Client-side handling |

## Accepted risks

- Lockout counters are not synced between Regions.
- Access tokens remain valid until expiry after member removal; keep lifetimes short.
- TOTP MFA isn't offered (email MFA only) because TOTP doesn't work in the secondary.
