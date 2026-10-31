"""Network tests. Run with: uv run pytest -m integration"""

import pytest

from hijackscan.fetch.common import Fetcher, load_config, parse_hrefs
from hijackscan.fetch.ris import month_index_url

pytestmark = pytest.mark.integration


def test_ris_month_index_uses_updates_prefix(tmp_path):
    cfg = load_config(overrides={"data_dir": str(tmp_path)})
    f = Fetcher(cfg)
    from datetime import UTC, datetime

    hrefs = parse_hrefs(f.get_text(month_index_url(cfg["ris"]["base_url"], "00", datetime(2026, 8, 1, tzinfo=UTC))))
    assert any(h.startswith("updates.20260828.") for h in hrefs)
    assert any(h.startswith("bview.20260828.0800") for h in hrefs)
