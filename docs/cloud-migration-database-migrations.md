# Cloud Migration Factory database migrations

Cloud Migration Factory schema changes are versioned with Alembic. The application still calls SQLAlchemy `create_all` so a new installation can bootstrap the legacy product tables; Alembic owns subsequent Cloud Migration Factory schema evolution.

## Release procedure

1. Back up the client-owned PostgreSQL database.
2. Set `DATABASE_URL` to the same secret-backed URL used by the backend.
3. Enable `database.migrations.enabled` so the Helm pre-upgrade Job runs `alembic upgrade head` before rolling out the new backend image. A first-time installation is bootstrapped by SQLAlchemy `create_all`; the first upgrade records and reconciles the Alembic baseline.
4. Confirm `alembic current` returns `20260718_0001`.
5. Roll out the backend and verify `/pipeline/api/health` and `/pipeline/api/cloud-migration/capabilities`.

The first migration is intentionally upgrade-safe for both existing databases created by `create_all` and new installations. It adds tenant-scoped endpoint and transfer-profile tables, then adds nullable references to existing project and wave records.

Do not put AWS keys, Druva credentials, passwords, or other secrets in the JSON configuration columns. Store only a reference to a client-controlled Kubernetes Secret or external secret manager.
