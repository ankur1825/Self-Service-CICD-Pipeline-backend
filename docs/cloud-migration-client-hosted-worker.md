# Client-hosted AWS execution worker

## Purpose

The worker executes migration operations inside the client's security boundary. The
Horizon API stores plans, approvals, job state, and evidence. It never stores AWS access
keys. The worker obtains short-lived AWS STS credentials for one job, uses an
action-specific session policy, and discards the credentials when the job finishes.

The first production increment supports:

- AWS identity/account and network preflight;
- AWS MGN source-server reconciliation;
- test launch and marking testing ready for cutover;
- cutover launch;
- rollback to ready-for-test or ready-for-cutover;
- cutover finalization behind a separate safety lock;
- durable leases, bounded retries, idempotency, separation of duties, audit events,
  and SHA-256 evidence artifacts.

## Safety model

| Control | Behavior |
| --- | --- |
| Data boundary | Jobs, results, and evidence remain in the client database. |
| Credentials | STS credentials are held only in worker memory for a short session. |
| Idempotency | Every API request requires a client-supplied `Idempotency-Key`. |
| Read-only jobs | `PREFLIGHT` and `RECONCILE` can run while AWS execution is locked. |
| Mutating jobs | Require an APPROVED wave, enabled execution lock, and a different approver. |
| Finalization | Also requires `finalizationEnabled=true`; it is intentionally independent. |
| Stale plans | A job will not run when its recorded plan version differs from the wave. |
| MGN lifecycle | Each action verifies the observed AWS lifecycle before making an API call. |
| Evidence | Success, retry, and terminal failure records are hashed and integrity-checked on read. |
| Liveness | Each worker records a database heartbeat; health becomes attention when it is stale. |
| Concurrency | A wave can have only one active mutation; tenant active-job count is bounded. |

## 1. Configure AWS identities

Use the Terraform examples in `deploy/aws/client-worker`:

1. Apply `worker-irsa` in the account containing the Horizon EKS cluster.
2. Apply `target-role` in the migration target account with `execution_enabled=false`.
3. Generate a unique external ID and store it in the client's secret manager.
4. Put the target role ARN in the Environment Catalog `target_aws_role_arn` field.
5. Put the IRSA role ARN on the worker service account annotation.

Start with the target role's read-only policy. Add the mutation permissions only after
the client security owner approves execution.

## 2. Configure the network

The worker checks TLS/TCP 443 to the regional STS and MGN endpoints. The MGN replication
agent also needs TCP 443 to MGN and TCP 1500 to every replication server in the staging
subnet. A TCP 1500 test is meaningful only when the worker has the same routed network
vantage as the source servers. Deploy the worker in that source-connected client network
or use a client-controlled probe there.

Supply replication-server DNS names or IP addresses in the PRELIGHT request. The worker
rejects loopback, link-local, multicast, unspecified, URL-shaped, and invalid targets.
A preflight without TCP 1500 targets is recorded as blocked rather than silently passed.

## 3. Enable the read-only worker

Use PostgreSQL for the API and worker. Then configure Helm values similar to:

```yaml
cloudMigration:
  aws:
    enabled: true
    executionEnabled: false
    finalizationEnabled: false
  worker:
    enabled: true
    executionMode: aws
    mockExecutionEnabled: false
    serviceAccount:
      annotations:
        eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/horizon-cloud-migration-worker
    awsExternalIdSecret:
      existingSecret: cloud-migration-aws-external-id
      key: CLOUD_MIGRATION_AWS_EXTERNAL_ID
```

Run `alembic upgrade head` before starting the new API or worker image. The worker has no
Ingress or Service and polls the client database for durable jobs.

Use `GET /cloud-migration/execution/health` to verify a live heartbeat, queue depth,
expired leases, execution mode, and installation locks before opening a change window.

## 4. Run preflight and reconciliation

The examples assume the application's existing authenticated session token:

```bash
curl -X POST "$BASE_URL/cloud-migration/waves/$WAVE_ID/jobs/preflight" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: preflight:$WAVE_ID:001" \
  -d '{"tcp1500_hosts":["10.20.30.41","10.20.30.42"]}'
```

```bash
curl -X POST "$BASE_URL/cloud-migration/waves/$WAVE_ID/jobs/reconcile" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: reconcile:$WAVE_ID:001" \
  -d '{}'
```

Query the job until it is `SUCCEEDED` or `FAILED`:

```bash
curl -H "Authorization: Bearer $SESSION_TOKEN" \
  "$BASE_URL/cloud-migration/jobs/$JOB_ID"
```

Do not enable mutation permissions until preflight reports `ready=true`, every workload
resolves to an MGN source server, replication is healthy, and the wave plan is approved.

## 5. Execute test and cutover

Set the target Terraform module `execution_enabled=true`, then set
`cloudMigration.aws.executionEnabled=true`. An operator requests an action. The API
returns `AWAITING_APPROVAL`:

```bash
curl -X POST "$BASE_URL/cloud-migration/waves/$WAVE_ID/jobs/start-test" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: start-test:$WAVE_ID:001" \
  -d '{}'
```

A different approver must approve the exact job version and confirmation phrase:

```bash
curl -X POST "$BASE_URL/cloud-migration/jobs/$JOB_ID/approve" \
  -H "Authorization: Bearer $APPROVER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"expected_version\":1,\"confirmation\":\"START_TEST $WAVE_ID\",\"comment\":\"CAB-2002\"}"
```

Repeat the request/approval pattern in this order:

1. `start-test` with confirmation `START_TEST <wave-id>`.
2. Validate the launched test instances and application acceptance criteria.
3. `finalize-test` with confirmation `FINALIZE_TEST <wave-id>` to mark MGN ready for cutover.
4. Stop source writes through the client's approved change procedure.
5. Run one final `reconcile` and confirm replication lag/backlog meet the client's RPO.
6. `start-cutover` with confirmation `START_CUTOVER <wave-id>`.
7. Validate the cutover instances, DNS, monitoring, security tooling, and business checks.
8. If validation fails, request `rollback` with `rollback_to` set to
   `ready-for-cutover` and confirmation `ROLLBACK <wave-id>`.
9. Only when the business owner accepts the cutover, enable the independent finalization
   lock and request `finalize-cutover` with confirmation `FINALIZE_CUTOVER <wave-id>`.

Finalizing an MGN cutover stops replication and begins cleanup of MGN replication
resources. Treat it as an irreversible change-control step, not a routine retry.

## 6. Verify evidence

The job response lists evidence IDs and their expected SHA-256 digests. Retrieve an
artifact with:

```bash
curl -H "Authorization: Bearer $AUDITOR_TOKEN" \
  "$BASE_URL/cloud-migration/evidence/$EVIDENCE_ID"
```

The API recomputes the payload digest and returns `integrity_verified`. Export these
client-owned artifacts into the client's evidence retention system after finalization.

## Development namespace status

The `horizon-cloud-migration-dev` values run the worker in explicit `mock` mode for
end-to-end acceptance. The pod has no service-account token and its NetworkPolicy allows
only PostgreSQL egress, so it cannot call AWS. See `cloud-migration-mock-acceptance.md`.
Configure a real sandbox account, IRSA role, target role, external ID, MGN initialization,
and TCP 1500 targets in a separate values file before any `aws`-mode test.
