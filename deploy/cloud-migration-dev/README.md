# `horizon-cloud-migration-dev` deployment overlay

For the client-hosted AWS worker, IAM model, safety locks, and execution API, see
[`../../docs/cloud-migration-client-hosted-worker.md`](../../docs/cloud-migration-client-hosted-worker.md).

This overlay deploys the feature-branch control plane without changing `horizon-relevance-dev`. AWS execution, license sync, usage reporting, Jenkins integration, and self-approval are disabled.

## Prerequisites

- Immutable backend and UI images built from the feature commits and pushed to ECR.
- DNS for `cloud-migration-dev.horizonrelevance.com` pointing to the existing ingress load balancer.
- The development LDAP groups listed in `backend-values.yaml` and at least two different test users.
- A 12-digit sandbox AWS account ID. Never use a production account for this environment.
- `aws`, `docker` or `podman`, `kubectl`, and Helm configured for the development account and cluster.

Keep the UI and backend on `feature/cloud-migration-enterprise`. Do not merge either branch to `main` until this isolated release has passed acceptance testing.

## Build and publish immutable images

Build each repository at its exact feature commit and use the full commit SHA as the ECR tag:

```bash
export CLOUD_MIGRATION_BACKEND_SHA="$(git rev-parse HEAD)"
docker build --pull -t 426946630837.dkr.ecr.us-east-1.amazonaws.com/horizon/backend:"${CLOUD_MIGRATION_BACKEND_SHA}" .
docker push 426946630837.dkr.ecr.us-east-1.amazonaws.com/horizon/backend:"${CLOUD_MIGRATION_BACKEND_SHA}"
```

From the UI repository:

```bash
export CLOUD_MIGRATION_UI_SHA="$(git rev-parse HEAD)"
docker build --pull -t 426946630837.dkr.ecr.us-east-1.amazonaws.com/horizon/frontend:"${CLOUD_MIGRATION_UI_SHA}" .
docker push 426946630837.dkr.ecr.us-east-1.amazonaws.com/horizon/frontend:"${CLOUD_MIGRATION_UI_SHA}"
```

Authenticate Docker to ECR first if necessary. Never deploy `latest` or a mutable release tag to this namespace.

## Generate development-only secrets

```bash
python3 deploy/cloud-migration-dev/prepare_secrets.py --aws-account-id 111122223333
```

The command prompts for the existing development LDAP bind password and writes ignored files under `.local/`. It does not modify the cluster.

## Render before applying

```bash
kubectl apply --dry-run=server -f deploy/cloud-migration-dev/platform.yaml
helm template horizon-cloud-migration-backend horizon-self-service-cicd-pipeline-backend \
  -f deploy/cloud-migration-dev/backend-values.yaml \
  -f .local/cloud-migration-dev-generated-values.json \
  --set-string image.tag=BACKEND_COMMIT_SHA
```

Render the UI chart from the UI repository with its matching overlay and immutable image tag.

## Deployment order

1. Apply `platform.yaml` to create the namespace, quotas, PostgreSQL, and network policies.
2. Apply `.local/cloud-migration-dev-secrets.json`.
3. Install the backend Helm release.
4. Install the UI Helm release.
5. Verify probes and run the control-plane acceptance workflow.

The corresponding commands are:

```bash
kubectl apply -f deploy/cloud-migration-dev/platform.yaml
kubectl apply -f .local/cloud-migration-dev-secrets.json

helm upgrade --install cloud-migration-backend horizon-self-service-cicd-pipeline-backend \
  --namespace horizon-cloud-migration-dev \
  --values deploy/cloud-migration-dev/backend-values.yaml \
  --values .local/cloud-migration-dev-generated-values.json \
  --set-string image.tag="${CLOUD_MIGRATION_BACKEND_SHA}" \
  --atomic --wait --timeout 10m
```

From the UI repository:

```bash
helm upgrade --install cloud-migration-ui horizon-self-service-cicd-pipeline-ui-dashboard \
  --namespace horizon-cloud-migration-dev \
  --values deploy/cloud-migration-dev/ui-values.yaml \
  --set-string image.tag="${CLOUD_MIGRATION_UI_SHA}" \
  --atomic --wait --timeout 10m

kubectl rollout status deployment/horizon-cloud-migration-ui -n horizon-cloud-migration-dev --timeout=5m
kubectl rollout status deployment/horizon-cloud-migration-backend -n horizon-cloud-migration-dev --timeout=5m
```

Record both commit SHAs, image digests, rendered Helm values, test evidence, and approver identity for the release evidence bundle.

Do not set `cloudMigration.aws.executionEnabled=true`; the client-hosted execution worker is a later gated phase.
