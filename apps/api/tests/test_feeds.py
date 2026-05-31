"""Tests du parsing de feed + repli blocklist (sans réseau ni Redis)."""
from __future__ import annotations

import pytest

from app.services import feeds, threatintel


def test_parse_ips_skips_comments_and_invalid() -> None:
    text = "\n".join(
        [
            "# Feodo Tracker blocklist",
            "",
            "1.2.3.4",
            "5.6.7.8,443,online",  # format CSV → on garde le 1er champ
            "not-an-ip",
            "10.0.0.1",
        ]
    )
    ips = feeds._parse_ips(text)
    assert ips == {"1.2.3.4", "5.6.7.8", "10.0.0.1"}


def test_parse_ips_empty() -> None:
    assert feeds._parse_ips("# header only\n\n") == set()


@pytest.mark.asyncio
async def test_load_blocklist_falls_back_to_embedded() -> None:
    # Redis injoignable en test → l'union retombe sur la liste embarquée.
    ips = await threatintel.load_blocklist()
    assert threatintel.BLOCKLIST_IPS <= ips
