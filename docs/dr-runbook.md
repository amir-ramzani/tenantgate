# DR runbook

Targets (plan §9):

| | Target |
|---|---|
| Identity RPO | seconds (replication is eventually consistent) |
| Identity RTO | health-check detection + DNS TTL, < 10 minutes |
| Control plane | unavailable for writes until the primary recovers (accepted) |

## Signals

- Alarm `tenantgate-<stage>-auth-unhealthy` (primary): the canary can't get tokens.
- Route 53 health check `tenantgate-<stage>-auth`: follows that alarm.
- `GET https://api.<domain>/demo/health` → `X-Served-Region` shows who is serving.
- `GET https://api.<domain>/control/status` → `region_role`, `auth_mode`, `writes_allowed`.

## Automatic failover (what should happen)

1. Canary fails three minutes in a row → alarm → health check unhealthy.
2. Cognito routes `auth.<domain>` (managed login, `/oauth2/token`) to the replica.
3. Route 53 answers `api.<domain>` with the secondary's API.
4. The secondary control plane is already in `failover` mode: reads work, writes return `503`.

## Operator checklist during an incident

1. Confirm the alarm is real (CloudWatch canary metrics, AWS Health Dashboard).
2. Set the primary's flag so nothing writes even if the primary half-recovers:
   `aws ssm put-parameter --name /tenantgate/<stage>/auth-mode --value failover --overwrite --region <primary>`
3. Post status: sign-in and APIs work; tenant onboarding, invitations, password
   resets and M2M rotation are paused.
4. Watch secondary trigger errors and throttling.

## Failback (manual)

Do this only after the primary has been healthy for at least 30 minutes.

1. Check the canary metric is back to 1 and the alarm is `OK`.
2. If the health check was forced (drill), revert it: set
   `/tenantgate/<stage>/canary-force` to `off`, or `Inverted=false` on the health check.
3. Wait for `X-Served-Region` to show the primary.
4. Set `/tenantgate/<stage>/auth-mode` back to `normal` in the primary.
5. Run `pytest -m integration` against the primary.
6. Review anything that queued up during failover (invites, rotations).

## Drill

```bash
python scripts/dr_drill.py --domain example.com --stage dev \
  --primary ap-southeast-1 --secondary ap-southeast-2 --report drill.json [--failback]
```

The script forces failover (via the canary by default), measures the time until
the secondary serves traffic, runs the integration suite against it, and
optionally fails back. Mint a tenant M2M token before the drill and export it
as `TG_PRIMARY_TOKEN` to check that primary-issued tokens still validate.

## Drill log

| Date | Stage | Method | Failover (s) | Integration | Failback (s) | Notes |
|---|---|---|---|---|---|---|
| _not yet run_ | | | | | | |
