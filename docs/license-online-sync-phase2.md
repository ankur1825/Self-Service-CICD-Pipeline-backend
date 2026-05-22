# License Online Sync Phase 2

This backend integrates a client-hosted Horizon Relevance installation with the Horizon-owned License Management Service.

## Runtime Flow

1. Horizon creates the client, subscription, and activation token in the License Management Service.
2. The client stores the activation token as a Kubernetes Secret.
3. Backend Helm values define the client identity, installation identity, AWS account binding, and license sync endpoint.
4. The frontend License page calls `POST /license/sync`.
5. The backend sends the activation token and installation metadata to Horizon.
6. Horizon returns a signed entitlement document.
7. The backend validates the entitlement, stores it in the local cache file, and enforces it for pipeline requests.

## Required Backend Helm Values

```yaml
enterprise:
  licenseEnforcementEnabled: true
  clientId: acme-fintech
  clientName: "Acme Fintech"
  installationId: acme-fintech-prod-us-east-1
  awsAccountId: "123456789012"
  awsRegion: us-east-1
  productVersion: "1.4.28"
  licenseMode: online-sync
  licenseSyncEndpoint: https://license.horizonrelevance.com/api/v1/licenses/sync
  licenseUpgradeEndpoint: https://license.horizonrelevance.com/api/v1/licenses/upgrade-requests
  licenseCacheFile: /app/data/enterprise-license-cache.json
  activationTokenSecret:
    existingSecret: horizon-license-activation
    key: ENTERPRISE_LICENSE_ACTIVATION_TOKEN
  signingSecret:
    existingSecret: horizon-license-verifier
    key: ENTERPRISE_LICENSE_SIGNING_SECRET
```

## Kubernetes Secrets

```bash
kubectl create secret generic horizon-license-activation \
  -n <platform-namespace> \
  --from-literal=ENTERPRISE_LICENSE_ACTIVATION_TOKEN='<activation-token>'

kubectl create secret generic horizon-license-verifier \
  -n <platform-namespace> \
  --from-literal=ENTERPRISE_LICENSE_SIGNING_SECRET='<shared-dev-signing-secret>'
```

For production, replace the shared HMAC verifier with public-key verification when the License Management Service is moved to KMS asymmetric signing.

## API Contract

The backend sends this payload to the Horizon License Management Service:

```json
{
  "client_id": "acme-fintech",
  "client_name": "Acme Fintech",
  "installation_id": "acme-fintech-prod-us-east-1",
  "activation_token": "stored-in-kubernetes-secret",
  "aws_account_id": "123456789012",
  "region": "us-east-1",
  "product_version": "1.4.28",
  "current_license_key": "optional-current-license",
  "current_expires_at": "optional-current-expiry",
  "force": true,
  "platform": {
    "product": "Horizon Relevance AI DevSecOps Platform",
    "backend_root_path": "/pipeline/api",
    "license_mode": "online-sync"
  }
}
```

## Client-Facing Behavior

The License page shows the synced entitlement, allowed environments, enabled pipelines, enabled features, account bindings, and expiration. Client admins do not type the license signature or license key manually for online-sync deployments.

## Phase 6 Upgrade Request Flow

Phase 6 lets the client admin request a commercial upgrade from the client-hosted License page without editing Helm values or license payloads.

1. Client admin opens **License** in the product UI.
2. Client admin reviews the current trial or enterprise entitlement.
3. Client admin fills in the enterprise upgrade request fields and submits.
4. Backend posts the request to Horizon's License Management Service through `ENTERPRISE_LICENSE_UPGRADE_ENDPOINT`.
5. Horizon operators review the request in the Horizon License Operations Portal.
6. Horizon creates a commercial offer and activates it after acceptance/payment.
7. Client admin clicks **Sync License** to receive the upgraded signed entitlement.

The backend derives `ENTERPRISE_LICENSE_UPGRADE_ENDPOINT` automatically from `ENTERPRISE_LICENSE_SYNC_ENDPOINT` when the sync endpoint ends in `/api/v1/licenses/sync`. Set `licenseUpgradeEndpoint` explicitly when the license service is exposed through a different route.
