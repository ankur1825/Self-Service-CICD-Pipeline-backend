# Cloud Migration Factory — Mock Acceptance Runbook

This runbook validates the complete client-hosted AWS rehost control flow without
calling AWS or changing an EC2/MGN resource. It is intended only for a dedicated
development namespace.

## Safety boundary

The worker starts in mock mode only when both settings are present:

```text
CLOUD_MIGRATION_EXECUTION_MODE=mock
CLOUD_MIGRATION_MOCK_EXECUTION_ENABLED=true
```

The `horizon-cloud-migration-dev` worker also runs without a Kubernetes service
account token and its NetworkPolicy permits egress only to the namespace-local
PostgreSQL service. Mock results contain `mock: true`, `execution_mode: mock`, and
a warning that no AWS operation occurred.

Never reuse the development mock values file in a production namespace.

## Roles used for acceptance

- Migration architect/operator: creates the project and wave, generates the plan,
  and requests actions.
- Migration approver: approves the plan and each mutating action. This must be a
  different identity from the requester.
- Migration auditor: reads jobs, audit events, and hashed evidence.

The feature remains protected by the `Cloud Migration Factory`,
`cloud_migration`, and `cloud_migration_aws` license entitlements.

## Happy-path acceptance

1. Create an on-premises VMware-to-AWS project using the DEV Environment Catalog
   target.
2. Add a wave with one or more representative source server names.
3. Generate the AWS MGN plan and resolve every blocking plan check.
4. Sign in as a different migration approver and approve the plan.
5. Run **Preflight**. Confirm all simulated STS, MGN, and TCP 1500 checks pass.
6. Run **Reconcile MGN**. Confirm every workload becomes `TEST_READY`.
7. Request **Launch test**. Confirm it stays `AWAITING_APPROVAL` until a different
   approver types the exact confirmation shown by the UI.
8. Confirm the worker completes the job and the wave becomes `TEST_IN_PROGRESS`.
9. Request and separately approve **Finalize test**. Confirm `CUTOVER_READY`.
10. Request and separately approve **Start cutover**. Confirm
    `CUTOVER_IN_PROGRESS`.
11. Request and separately approve **Finalize cutover**. Confirm the wave is
    `FINALIZED` and every workload is `CUTOVER_COMPLETE`.
12. Open every evidence item. Confirm `SHA-256 integrity verified`, actor identities,
    plan version, action, outcome, timestamps, and `mock: true`.

## Rollback acceptance

Use a second approved wave so the finalization test remains intact.

1. Reconcile until the wave is `TEST_READY`.
2. Request, separately approve, and complete **Launch test**.
3. Request and separately approve **Roll back**.
4. Confirm the workload returns to `TEST_READY`, the mock launched instance ID is
   cleared, and rollback evidence passes its SHA-256 integrity check.

## Required technical checks

- Backend, UI, PostgreSQL, and worker pods are Ready with zero unexpected restarts.
- `/cloud-migration/execution/health` reports `healthy`, `mock`, zero expired
  leases, and no stuck queued/running jobs after the test.
- A repeated request with the same idempotency key returns the original job.
- A second mutation cannot be requested while one is active for the wave.
- The requester cannot approve their own mutation.
- The mock safety lock blocks mutations when disabled.
- No worker AWS credential variables or service-account token are mounted.
- The production namespace and `main` branch are unchanged.

## Gate for later real AWS acceptance

Mock acceptance does not approve real migration. Real AWS testing requires a
separate change record covering client-owned IAM/IRSA, STS account validation,
MGN initialization, source-to-staging TCP 1500, AWS endpoint TCP 443, a disposable
test server, budgets, maintenance window, rollback owner, and evidence retention.
Only then may a dedicated values file use `executionMode: aws`; it must set
`mockExecutionEnabled: false`. Finalization remains locked until the test launch,
application validation, and rollback rehearsal have been accepted.
