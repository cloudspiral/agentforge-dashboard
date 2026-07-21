"""Guard committed public JSON Schemas against unnoticed contract drift."""

import runpy
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPORTER = runpy.run_path(str(REPOSITORY_ROOT / "scripts" / "export_contracts.py"))
SCHEMA_MODELS = EXPORTER["SCHEMA_MODELS"]
schema_drift = EXPORTER["schema_drift"]


def test_committed_contract_schemas_match_generated_models() -> None:
    output_dir = REPOSITORY_ROOT / "contracts" / "v1"
    assert schema_drift(output_dir) == []
    assert {path.name for path in output_dir.glob("*.schema.json")} == set(SCHEMA_MODELS)


def test_schema_destination_is_inside_repository() -> None:
    output_dir = (REPOSITORY_ROOT / "contracts" / "v1").resolve()
    assert output_dir.is_relative_to(Path(REPOSITORY_ROOT).resolve())
