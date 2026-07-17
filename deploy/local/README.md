# Local Cloud Migration control plane

This stack validates the feature branch without accessing AWS or the vendor licensing service. It runs UI, backend, PostgreSQL, and an isolated OpenLDAP directory with one user per migration role.

## Prepare

From the backend repository:

```bash
python3 deploy/local/prepare.py --aws-account-id 111122223333
```

Use only a sandbox account ID. The generated `.local` directory is ignored by Git and contains a signed local-only license and generated runtime secrets.

## Start

Docker Compose:

```bash
docker compose --env-file .local/runtime.env -f compose.cloud-migration.yaml up --build -d
```

Podman Compose:

```bash
podman compose --env-file .local/runtime.env -f compose.cloud-migration.yaml up --build -d
```

Open `http://127.0.0.1:8080/pipeline/` and sign in with any fixture user. The local-only password is `MigrationTest!2026`.

## Automated acceptance test

```bash
python3 deploy/local/smoke_test.py
```

The test verifies signed licensing, tenant/account scope, project and wave persistence, versioned planning, separation of duties, audit history, and that AWS execution is disabled.

## Stop

```bash
docker compose --env-file .local/runtime.env -f compose.cloud-migration.yaml down
```

Add `--volumes` only when intentionally discarding the local PostgreSQL and LDAP data.
