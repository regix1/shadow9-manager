"""Tests for the interactive menu."""

from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from shadow9.config import Config
import shadow9.menu as menu_module


def test_view_config_shows_wireguard_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The settings menu shows the configured WireGuard values without a private key."""
    config = Config()
    config.wireguard.enabled = True
    config.wireguard.listen_port = 52001
    config.wireguard.enrollment_host = "0.0.0.0"
    config.wireguard.enrollment_port = 8201
    config.wireguard.tunnel_network = "10.88.0.0/24"
    config.wireguard.hub_endpoint = "hub.example.test:52001"
    config.wireguard.mtu = 1360
    config.wireguard.dns = ["10.88.0.1", "9.9.9.9"]
    config.wireguard.keepalive = 17

    def paths() -> SimpleNamespace:
        return SimpleNamespace(config_file=Path(__file__))

    def load_config(_cls: type[Config], _config_file: Path | None = None) -> Config:
        return config

    output = StringIO()
    monkeypatch.setattr(menu_module, "get_paths", paths)
    monkeypatch.setattr(menu_module.Config, "load", classmethod(load_config))
    monkeypatch.setattr(
        menu_module,
        "console",
        Console(file=output, force_terminal=False, color_system=None, width=160),
    )

    menu_module._action_view_config()

    rendered = output.getvalue()
    assert "WireGuard Configuration" in rendered
    assert "52001" in rendered
    assert "0.0.0.0" in rendered
    assert "8201" in rendered
    assert "10.88.0.0/24" in rendered
    assert "hub.example.test:52001" in rendered
    assert "1360" in rendered
    assert "10.88.0.1, 9.9.9.9" in rendered
    assert "17s" in rendered
    assert "private key" not in rendered.lower()
