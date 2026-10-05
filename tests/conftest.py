import json
from pathlib import Path

import pytest
import yaml

from rbac_audit.config import parse_config

FIXTURES = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent
TENANT = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SUB = "11111111-1111-1111-1111-111111111111"
U1, U2, G1, SP1, MI1, ORPH = (f"0000000{c}-0000-0000-0000-00000000000{n}" for c, n in
                              [("a", 1), ("a", 2), ("b", 1), ("c", 1), ("c", 2), ("d", 1)])


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def cfg(tmp_path):
    raw = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    raw["tenant_id"] = TENANT
    raw["scope"]["subscriptions"] = [SUB]
    raw["output_dir"] = str(tmp_path / "evidence")
    return parse_config(raw)
