# Real AWS sandbox gate

This overlay validates the client-hosted execution identity before a full real-mode
control plane is deployed. It is intentionally separate from
`horizon-cloud-migration-dev`, which remains the deterministic mock/UAT environment.

The checked-in job is pinned to an immutable backend image digest. It verifies:

1. DNS and TLS connectivity to the regional STS and MGN APIs.
2. IRSA identity for the dedicated EKS worker service account.
3. STS `AssumeRole` into the dedicated target execution role using an external ID.
4. Read-only MGN access from the assumed role.

The target role must contain only `mgn:DescribeJobs` and
`mgn:DescribeSourceServers` during this gate. Do not enable MGN mutation actions,
test launch, cutover, or finalization here.

## Secret and apply

Create `cloud-migration-aws-external-id` out of band. Never commit the value or put
it in Helm values:

```bash
kubectl create namespace horizon-cloud-migration-aws-sandbox --dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic cloud-migration-aws-external-id \
  --namespace horizon-cloud-migration-aws-sandbox \
  --from-literal=external-id="${HORIZON_AWS_EXTERNAL_ID}" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/cloud-migration-aws-sandbox/preflight.yaml
kubectl wait --for=condition=complete \
  job/horizon-cloud-migration-aws-preflight \
  --namespace horizon-cloud-migration-aws-sandbox --timeout=3m
kubectl logs job/horizon-cloud-migration-aws-preflight \
  --namespace horizon-cloud-migration-aws-sandbox
```

The preflight does not probe TCP/1500. That check must be run from the actual
source-server network because an EKS-originated probe does not prove the on-premises
replication path to MGN staging servers.

## Promotion gates

- Configure an encrypted MGN replication template before registering a source.
- Select one disposable, non-sensitive source server and record its MGN `s-...` ID.
- Re-run this job until every check passes.
- Enable only test-launch permissions for the first live test.
- Keep cutover and finalization disabled until separate approvals are recorded.
