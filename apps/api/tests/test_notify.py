"""Tests du service de notifications (gating + format, sans réseau)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from app.services import notify


@pytest.mark.asyncio
async def test_disabled_by_default() -> None:
    with patch.object(notify, "_post") as p:
        sent = await notify.maybe_notify(severity="critical", title="t", message="m")
    assert sent is False
    p.assert_not_called()


@pytest.mark.asyncio
async def test_below_threshold_not_sent() -> None:
    with patch.object(notify.settings, "notify_enabled", True), patch.object(
        notify.settings, "notify_webhook_url", "http://hook"
    ), patch.object(notify.settings, "notify_min_severity", "high"), patch.object(
        notify, "_post"
    ) as p:
        sent = await notify.maybe_notify(severity="low", title="t", message="m")
    assert sent is False
    p.assert_not_called()


@pytest.mark.asyncio
async def test_sent_when_threshold_met() -> None:
    with patch.object(notify.settings, "notify_enabled", True), patch.object(
        notify.settings, "notify_webhook_url", "http://hook"
    ), patch.object(notify.settings, "notify_min_severity", "high"), patch.object(
        notify, "_post"
    ) as p:
        sent = await notify.maybe_notify(severity="critical", title="arp_spoof", message="m")
    assert sent is True
    p.assert_called_once()


def test_payload_formats() -> None:
    with patch.object(notify.settings, "notify_format", "slack"):
        assert notify._payload("x", "high", "t", "m") == {"text": "x"}
    with patch.object(notify.settings, "notify_format", "discord"):
        assert notify._payload("x", "high", "t", "m") == {"content": "x"}
    with patch.object(notify.settings, "notify_format", "generic"):
        out = notify._payload("x", "high", "t", "m")
        assert out["severity"] == "high" and out["text"] == "x"
