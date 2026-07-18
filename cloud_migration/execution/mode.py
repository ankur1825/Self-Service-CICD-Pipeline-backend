import os


REAL_EXECUTION_MODE = "aws"
MOCK_EXECUTION_MODE = "mock"
SUPPORTED_EXECUTION_MODES = {REAL_EXECUTION_MODE, MOCK_EXECUTION_MODE}


def execution_mode() -> str:
    mode = os.getenv("CLOUD_MIGRATION_EXECUTION_MODE", REAL_EXECUTION_MODE).strip().lower()
    if mode not in SUPPORTED_EXECUTION_MODES:
        raise RuntimeError(
            "CLOUD_MIGRATION_EXECUTION_MODE must be either 'aws' or 'mock'."
        )
    return mode


def mock_execution_enabled() -> bool:
    value = os.getenv("CLOUD_MIGRATION_MOCK_EXECUTION_ENABLED", "false")
    return value.strip().lower() in {"1", "true", "yes", "on"}


def validate_execution_mode() -> str:
    mode = execution_mode()
    if mode == MOCK_EXECUTION_MODE and not mock_execution_enabled():
        raise RuntimeError(
            "Mock execution mode requires CLOUD_MIGRATION_MOCK_EXECUTION_ENABLED=true."
        )
    return mode
