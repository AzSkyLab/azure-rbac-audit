import pytest
import yaml

from rbac_audit.config import ConfigError, load_config, parse_config
from conftest import ROOT, TENANT


def base():
    raw = yaml.safe_load((ROOT / "config.example.yaml").read_text())
    raw["tenant_id"] = TENANT
    return raw


def test_example_config_parses_after_setting_tenant():
    cfg = parse_config(base())
    assert "Owner" in cfg.privileged_admin_roles and cfg.review_frequency_days == 90


def test_placeholder_tenant_rejected():
    with pytest.raises(ConfigError):
        load_config(ROOT / "config.example.yaml")


def test_empty_privileged_lists_rejected():
    raw = base()
    raw["privileged_roles"]["privileged_admin"] = []
    with pytest.raises(ConfigError):
        parse_config(raw)


def test_bad_subscription_rejected():
    raw = base()
    raw["scope"]["subscriptions"] = ["not-a-guid"]
    with pytest.raises(ConfigError):
        parse_config(raw)
