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
  productVersion: "1.4.29"
  licenseMode: online-sync
  licenseSyncEndpoint: https://license.horizonrelevance.com/api/v1/licenses/sync
  licenseUpgradeEndpoint: https://license.horizonrelevance.com/api/v1/licenses/upgrade-requests
  licenseCacheFile: /app/data/enterprise-license-cache.json
  licenseSignatureVerificationRequired: true
  activationTokenSecret:
    existingSecret: horizon-license-activation
    key: ENTERPRISE_LICENSE_ACTIVATION_TOKEN
  publicKeySecret:
    existingSecret: horizon-license-public-key
    key: ENTERPRISE_LICENSE_PUBLIC_KEY_PEM
```

## Kubernetes Secrets

```bash
kubectl create secret generic horizon-license-activation \
  -n <platform-namespace> \
  --from-literal=ENTERPRISE_LICENSE_ACTIVATION_TOKEN='<activation-token>'

kubectl create secret generic horizon-license-public-key \
  -n <platform-namespace> \
  --from-file=ENTERPRISE_LICENSE_PUBLIC_KEY_PEM=./horizon-license-public-key.pem
```

For production, use public-key verification. The Horizon License Management Service signs entitlements with an AWS KMS asymmetric signing key and the client-hosted backend verifies with the exported public key only. The client does not receive Horizon's private signing material.

For key rotation, provide a key-set secret instead of a single PEM:

```bash
kubectl create secret generic horizon-license-public-key-set \
  -n <platform-namespace> \
  --from-file=ENTERPRISE_LICENSE_PUBLIC_KEY_SET_JSON=./horizon-license-public-keys.json
```

Example key-set JSON:

```json
{
  "keys": [
    {
      "key_id": "arn:aws:kms:us-east-1:111122223333:key/current",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    },
    {
      "key_id": "arn:aws:kms:us-east-1:111122223333:key/previous",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"
    }
  ]
}
```

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
  "product_version": "1.4.29",
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

## Phase 7 Asymmetric Signature Verification

Phase 7 removes the production need for shared HMAC signing secrets in client-hosted deployments.

1. Horizon License Management Service runs with `HORIZON_LICENSE_SIGNING_MODE=aws-kms`.
2. Horizon signs each license entitlement with an AWS KMS asymmetric signing key.
3. The license payload includes `signature_mode`, `signature_algorithm`, `signature_key_id`, `signature_format`, and `signature_input`.
4. Horizon gives the client only the public key, either as a single PEM or as a key-set JSON for rotation.
5. The client-hosted backend verifies the license signature locally before enforcing pipelines, environments, AWS account bindings, installation binding, and feature entitlements.
6. During key rotation, Horizon signs new licenses with the new KMS key while the client backend can trust both the current and previous public keys through `ENTERPRISE_LICENSE_PUBLIC_KEY_SET_JSON`.

Recommended production values:

```yaml
enterprise:
  licenseEnforcementEnabled: true
  licenseMode: online-sync
  licenseSignatureVerificationRequired: true
  activationTokenSecret:
    existingSecret: horizon-license-activation
    key: ENTERPRISE_LICENSE_ACTIVATION_TOKEN
  publicKeySetSecret:
    existingSecret: horizon-license-public-key-set
    key: ENTERPRISE_LICENSE_PUBLIC_KEY_SET_JSON
```

Keep `signingSecret` empty for production asymmetric verification. It remains available only for local development or legacy HMAC licenses.

## Production Operations: Scheduled Sync And Grace

Client-hosted enterprise deployments should enable scheduled online sync so license upgrades, renewals, suspensions, and revocations are detected without requiring a human to click **Sync License**.

Recommended values:

```yaml
enterprise:
  licenseMode: online-sync
  licenseEnforcementEnabled: true
  licenseUsageReportingEnabled: true
  licenseAutoSyncEnabled: true
  licenseAutoSyncIntervalSeconds: "21600"
  licenseCacheGraceHours: "72"
```

Behavior:

- `licenseAutoSyncEnabled` starts a lightweight backend thread that syncs with Horizon on a fixed interval.
- `licenseAutoSyncIntervalSeconds` defaults to 6 hours and has a 5 minute minimum.
- `licenseCacheGraceHours` lets an already synced online license continue temporarily if the license service is unreachable or renewal is delayed.
- A revoked, suspended, inactive, or disabled entitlement is denied.
- An expired entitlement outside the grace period is denied.

The grace window is not a commercial renewal. It is an outage cushion so a temporary network or license-service issue does not immediately break a client-hosted production pipeline.
