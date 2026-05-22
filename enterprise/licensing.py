import base64
import binascii
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


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _b64url_decode(value: str) -> bytes:
    normalized = value.encode("utf-8")
    normalized += b"=" * (-len(normalized) % 4)
    try:
        return base64.urlsafe_b64decode(normalized)
    except (binascii.Error, ValueError) as exc:
        raise LicenseValidationError("License signature is not valid base64url.") from exc


def _load_public_key_entries() -> list[Dict[str, str]]:
    entries: list[Dict[str, str]] = []

    inline_pem = os.getenv("ENTERPRISE_LICENSE_PUBLIC_KEY_PEM", "").strip()
    if inline_pem:
        entries.append({"key_id": os.getenv("ENTERPRISE_LICENSE_PUBLIC_KEY_ID", "").strip(), "pem": inline_pem})

    public_key_file = os.getenv("ENTERPRISE_LICENSE_PUBLIC_KEY_FILE", "").strip()
    if public_key_file:
        path = Path(public_key_file)
        if not path.exists():
            raise LicenseValidationError(f"Configured license public key file does not exist: {public_key_file}")
        entries.append({"key_id": os.getenv("ENTERPRISE_LICENSE_PUBLIC_KEY_ID", "").strip(), "pem": path.read_text().strip()})

    key_set_json = os.getenv("ENTERPRISE_LICENSE_PUBLIC_KEY_SET_JSON", "").strip()
    key_set_file = os.getenv("ENTERPRISE_LICENSE_PUBLIC_KEY_SET_FILE", "").strip()
    if key_set_file:
        path = Path(key_set_file)
        if not path.exists():
            raise LicenseValidationError(f"Configured license public key set file does not exist: {key_set_file}")
        key_set_json = path.read_text().strip()

    if key_set_json:
        try:
            key_set = json.loads(key_set_json)
        except json.JSONDecodeError as exc:
            raise LicenseValidationError("Configured license public key set JSON is invalid.") from exc

        if isinstance(key_set, dict) and isinstance(key_set.get("keys"), list):
            for item in key_set["keys"]:
                if isinstance(item, dict) and item.get("public_key_pem"):
                    entries.append({
                        "key_id": str(item.get("key_id") or item.get("kid") or ""),
                        "pem": str(item["public_key_pem"]).strip(),
                    })
        elif isinstance(key_set, dict):
            for key_id, pem in key_set.items():
                if isinstance(pem, str):
                    entries.append({"key_id": str(key_id), "pem": pem.strip()})

    return [entry for entry in entries if entry.get("pem")]


def _select_public_key(license_doc: Dict[str, Any]) -> str:
    entries = _load_public_key_entries()
    if not entries:
        raise LicenseValidationError("RSA license verification requires ENTERPRISE_LICENSE_PUBLIC_KEY_PEM or ENTERPRISE_LICENSE_PUBLIC_KEY_SET_JSON.")

    expected_key_id = str(license_doc.get("signature_key_id") or "").strip()
    if expected_key_id:
        for entry in entries:
            if entry.get("key_id") == expected_key_id:
                return entry["pem"]
        raise LicenseValidationError(f"No configured license public key matches signature_key_id '{expected_key_id}'.")

    return entries[0]["pem"]


def _verify_rsa_signature(license_doc: Dict[str, Any], signature: str, algorithm: str) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, utils
    except ImportError as exc:
        raise LicenseValidationError("cryptography package is required for RSA license verification.") from exc

    public_key_pem = _select_public_key(license_doc)
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    digest = hashlib.sha256(_canonical_payload(license_doc)).digest()
    signature_bytes = _b64url_decode(signature)

    normalized_algorithm = algorithm.upper()
    if normalized_algorithm in {"RSASSA_PKCS1_V1_5_SHA_256", "RS256"}:
        signature_padding = padding.PKCS1v15()
    elif normalized_algorithm in {"RSASSA_PSS_SHA_256", "PS256"}:
        signature_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size)
    else:
        raise LicenseValidationError(f"Unsupported RSA license signature algorithm '{algorithm}'.")

    try:
        public_key.verify(signature_bytes, digest, signature_padding, utils.Prehashed(hashes.SHA256()))
    except InvalidSignature as exc:
        raise LicenseValidationError("License signature is invalid.") from exc


def _verify_license_signature(license_doc: Dict[str, Any]) -> None:
    signature = license_doc.get("signature") or license_doc.get("license_signature")
    verification_required = _env_bool("ENTERPRISE_LICENSE_SIGNATURE_VERIFICATION_REQUIRED", True)
    if not signature:
        if verification_required:
            raise LicenseValidationError("Signed license is required.")
        return

    algorithm = str(license_doc.get("signature_algorithm") or "").strip().upper()
    signing_mode = str(license_doc.get("signature_mode") or "").strip().lower()
    secret = os.getenv("ENTERPRISE_LICENSE_SIGNING_SECRET", "").strip()

    if algorithm in {"HMAC_SHA256", ""} and (secret or signing_mode in {"", "local-hmac"}):
        if not secret:
            if verification_required:
                raise LicenseValidationError("HMAC license verification requires ENTERPRISE_LICENSE_SIGNING_SECRET.")
            return
        expected = _expected_signature(license_doc, secret)
        if not hmac.compare_digest(signature, expected):
            raise LicenseValidationError("License signature is invalid.")
        return

    if algorithm in {"RSASSA_PKCS1_V1_5_SHA_256", "RSASSA_PSS_SHA_256", "RS256", "PS256"} or signing_mode == "aws-kms":
        _verify_rsa_signature(license_doc, signature, algorithm or "RSASSA_PKCS1_V1_5_SHA_256")
        return

    if verification_required:
        raise LicenseValidationError(f"Unsupported license signature algorithm '{algorithm or signing_mode}'.")


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
        "allowed_environments": _split_csv(os.getenv("ENTERPRISE_ALLOWED_ENVIRONMENTS", "DEV,QA,STAGE,PROD,EKS-NONPROD,EKS-PROD")),
        "allowed_aws_account_ids": _split_csv(os.getenv("ENTERPRISE_ALLOWED_AWS_ACCOUNT_IDS", "")),
        "installation_id": os.getenv("ENTERPRISE_INSTALLATION_ID", ""),
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
        "signature_algorithm",
        "signature_key_id",
        "signature_mode",
        "signature_version",
        "signature_format",
        "signature_input",
        "enabled_pipelines",
        "enabled_features",
        "allowed_environments",
        "allowed_aws_account_ids",
        "installation_id",
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


def validate_license(
    license_doc: Dict[str, Any],
    pipeline_name: str,
    target_env: str,
    requested_features: Iterable[str],
    aws_account_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not license_enforcement_enabled():
        license_doc.setdefault("validation_mode", "disabled")
        license_doc.setdefault("status", "active")
        return license_doc

    if not license_doc.get("client_id"):
        raise LicenseValidationError("client_id is required when license enforcement is enabled.")
    if not license_doc.get("license_key"):
        raise LicenseValidationError("license_key is required when license enforcement is enabled.")

    _verify_license_signature(license_doc)

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

    allowed_aws_account_ids = license_doc.get("allowed_aws_account_ids") or _split_csv(os.getenv("ENTERPRISE_ALLOWED_AWS_ACCOUNT_IDS", ""))
    if allowed_aws_account_ids and aws_account_id and not _contains(allowed_aws_account_ids, aws_account_id):
        raise LicenseValidationError(f"AWS account '{aws_account_id}' is not enabled for this license.")

    expected_installation_id = license_doc.get("installation_id") or ""
    runtime_installation_id = os.getenv("ENTERPRISE_INSTALLATION_ID", "").strip()
    if expected_installation_id and runtime_installation_id and expected_installation_id != runtime_installation_id:
        raise LicenseValidationError("License is not valid for this product installation.")

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
        "license_key": license_doc.get("license_key"),
        "license_type": license_doc.get("license_type"),
        "issuer": license_doc.get("issuer"),
        "issued_at": license_doc.get("issued_at"),
        "expires_at": license_doc.get("expires_at"),
        "enabled_pipelines": license_doc.get("enabled_pipelines", []),
        "enabled_features": license_doc.get("enabled_features", []),
        "allowed_environments": license_doc.get("allowed_environments", []),
        "allowed_aws_account_ids": license_doc.get("allowed_aws_account_ids", []),
        "installation_id": license_doc.get("installation_id") or os.getenv("ENTERPRISE_INSTALLATION_ID", ""),
        "max_repos": license_doc.get("max_repos"),
        "max_builds_per_month": license_doc.get("max_builds_per_month"),
        "max_users": license_doc.get("max_users"),
        "status": license_doc.get("status", "unknown"),
        "validation_mode": license_doc.get("validation_mode", "unknown"),
        "license_mode": license_doc.get("license_mode") or os.getenv("ENTERPRISE_LICENSE_MODE", "offline-file"),
        "signature_algorithm": license_doc.get("signature_algorithm"),
        "signature_key_id": license_doc.get("signature_key_id"),
        "signature_mode": license_doc.get("signature_mode"),
        "last_synced_at": license_doc.get("last_synced_at"),
        "limits": license_doc.get("limits", {}),
    }
