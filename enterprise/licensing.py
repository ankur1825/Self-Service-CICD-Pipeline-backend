import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


class LicenseValidationError(ValueError):
    pass


def license_enforcement_enabled() -> bool:
    return os.getenv("ENTERPRISE_LICENSE_ENFORCEMENT_ENABLED", "false").lower() == "true"


def _canonical_payload(payload: Dict[str, Any]) -> bytes:
    signed_payload = {k: v for k, v in payload.items() if k not in {"signature", "license_signature"}}
    return json.dumps(signed_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _expected_signature(payload: Dict[str, Any], secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), _canonical_payload(payload), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")


def sign_license(payload: Dict[str, Any], secret: str) -> str:
    return _expected_signature(payload, secret)


def _split_csv(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _load_license_file() -> Dict[str, Any]:
    license_file = os.getenv("ENTERPRISE_LICENSE_FILE", "").strip()
    if not license_file:
        return {}
    path = Path(license_file)
    if not path.exists():
        raise LicenseValidationError(f"Configured license file does not exist: {license_file}")
    with path.open() as f:
        return json.load(f)


def _license_cache_path() -> Path:
    return Path(os.getenv("ENTERPRISE_LICENSE_CACHE_FILE", "/app/data/enterprise-license-cache.json"))


def load_cached_license() -> Dict[str, Any]:
    path = _license_cache_path()
    if not path.exists():
        return {}
    with path.open() as f:
        return json.load(f)


def save_cached_license(license_doc: Dict[str, Any]) -> Dict[str, Any]:
    path = _license_cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    cached_doc = {
        **license_doc,
        "last_synced_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    with path.open("w") as f:
        json.dump(cached_doc, f, indent=2, sort_keys=True)
    return cached_doc


def default_license_from_env() -> Dict[str, Any]:
    license_from_file = _load_license_file()
    if license_from_file:
        return license_from_file

    cached_license = load_cached_license()
    if cached_license:
        return cached_license

    return {
        "client_id": os.getenv("ENTERPRISE_CLIENT_ID", "horizon-internal"),
        "client_name": os.getenv("ENTERPRISE_CLIENT_NAME", "Horizon Relevance Internal"),
        "license_key": os.getenv("ENTERPRISE_LICENSE_KEY", "internal-dev-license"),
        "license_type": os.getenv("ENTERPRISE_LICENSE_TYPE", "internal"),
        "expires_at": os.getenv("ENTERPRISE_LICENSE_EXPIRES_AT", "2099-12-31T23:59:59Z"),
        "enabled_pipelines": _split_csv(os.getenv("ENTERPRISE_ENABLED_PIPELINES", "Devops Pipeline,Test Devops Pipeline,Prod Devops Pipeline")),
        "enabled_features": _split_csv(os.getenv("ENTERPRISE_ENABLED_FEATURES", "build,artifact_publish,code_scan,image_scan,policy_validation,static_application_security,test_suites,notifications,secret_management,prod_deploy,ai_remediation")),
        "allowed_environments": _split_csv(os.getenv("ENTERPRISE_ALLOWED_ENVIRONMENTS", "DEV,QA,STAGE,EKS-NONPROD,EKS-PROD")),
        "max_repos": int(os.getenv("ENTERPRISE_MAX_REPOS", "999999")),
        "max_builds_per_month": int(os.getenv("ENTERPRISE_MAX_BUILDS_PER_MONTH", "999999")),
        "max_users": int(os.getenv("ENTERPRISE_MAX_USERS", "999999")),
        "license_mode": os.getenv("ENTERPRISE_LICENSE_MODE", "offline-file"),
    }


def merge_request_license(request_values: Dict[str, Any]) -> Dict[str, Any]:
    license_doc = default_license_from_env()
    for key in [
        "client_id",
        "client_name",
        "license_key",
        "license_type",
        "license_signature",
        "license_expires_at",
        "enabled_pipelines",
        "enabled_features",
        "allowed_environments",
    ]:
        value = request_values.get(key)
        if value not in (None, "", []):
            normalized_key = "signature" if key == "license_signature" else key
            normalized_key = "expires_at" if key == "license_expires_at" else normalized_key
            license_doc[normalized_key] = value
    return license_doc


def _contains(values: Iterable[str], expected: str) -> bool:
    expected_normalized = expected.strip().lower()
    return any(item.strip().lower() == expected_normalized for item in values)


def validate_license(license_doc: Dict[str, Any], pipeline_name: str, target_env: str, requested_features: Iterable[str]) -> Dict[str, Any]:
    if not license_enforcement_enabled():
        license_doc.setdefault("validation_mode", "disabled")
        license_doc.setdefault("status", "active")
        return license_doc

    if not license_doc.get("client_id"):
        raise LicenseValidationError("client_id is required when license enforcement is enabled.")
    if not license_doc.get("license_key"):
        raise LicenseValidationError("license_key is required when license enforcement is enabled.")

    secret = os.getenv("ENTERPRISE_LICENSE_SIGNING_SECRET", "").strip()
    signature = license_doc.get("signature") or license_doc.get("license_signature")
    if secret:
        if not signature:
            raise LicenseValidationError("Signed license is required.")
        expected = _expected_signature(license_doc, secret)
        if not hmac.compare_digest(signature, expected):
            raise LicenseValidationError("License signature is invalid.")

    expires_at = license_doc.get("expires_at")
    if not expires_at:
        raise LicenseValidationError("License expiration is required.")
    if _parse_datetime(expires_at) <= datetime.now(timezone.utc):
        raise LicenseValidationError("License is expired.")

    enabled_pipelines = license_doc.get("enabled_pipelines") or []
    if enabled_pipelines and not _contains(enabled_pipelines, pipeline_name):
        raise LicenseValidationError(f"Pipeline '{pipeline_name}' is not enabled for this license.")

    allowed_environments = license_doc.get("allowed_environments") or []
    if allowed_environments and not _contains(allowed_environments, target_env):
        raise LicenseValidationError(f"Environment '{target_env}' is not enabled for this license.")

    enabled_features = license_doc.get("enabled_features") or []
    for feature in requested_features:
        if enabled_features and not _contains(enabled_features, feature):
            raise LicenseValidationError(f"Feature '{feature}' is not enabled for this license.")

    license_doc["validation_mode"] = "enforced"
    license_doc["status"] = "active"
    return license_doc


def license_summary(license_doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "client_id": license_doc.get("client_id"),
        "client_name": license_doc.get("client_name"),
        "license_type": license_doc.get("license_type"),
        "expires_at": license_doc.get("expires_at"),
        "enabled_pipelines": license_doc.get("enabled_pipelines", []),
        "enabled_features": license_doc.get("enabled_features", []),
        "allowed_environments": license_doc.get("allowed_environments", []),
        "max_repos": license_doc.get("max_repos"),
        "max_builds_per_month": license_doc.get("max_builds_per_month"),
        "max_users": license_doc.get("max_users"),
        "status": license_doc.get("status", "unknown"),
        "validation_mode": license_doc.get("validation_mode", "unknown"),
        "license_mode": license_doc.get("license_mode") or os.getenv("ENTERPRISE_LICENSE_MODE", "offline-file"),
        "last_synced_at": license_doc.get("last_synced_at"),
    }
