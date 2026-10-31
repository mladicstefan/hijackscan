from datetime import UTC, date, datetime

from hijackscan.fetch.common import resolve_date, resolve_datetime
from hijackscan.fetch.crtsh import Chunk, _split_to, month_key, months
from hijackscan.fetch.ris import last_bview_before, plan, update_times
from hijackscan.fetch.rpki import rpki_dates


def test_resolve_date_today_and_iso():
    assert resolve_date("2026-08-27") == date(2026, 8, 27)
    assert resolve_date("today") == datetime.now(UTC).date()
    assert resolve_date(date(2026, 1, 1)) == date(2026, 1, 1)


def test_resolve_datetime_z_suffix():
    assert resolve_datetime("2026-08-27T20:00Z") == datetime(2026, 8, 27, 20, 0, tzinfo=UTC)
    assert resolve_datetime("2026-08-27T20:00:00+02:00").utcoffset().total_seconds() == 7200


def test_rpki_dates_dedupe_and_today():
    ds = rpki_dates(["2026-08-28", "2026-08-28", "today"])
    assert ds[0] == date(2026, 8, 28)
    assert len(ds) == 2


def test_update_times_five_minute_grid_half_open():
    s = datetime(2026, 8, 28, 10, 0, tzinfo=UTC)
    e = datetime(2026, 8, 28, 10, 30, tzinfo=UTC)
    ts = update_times(s, e)
    assert len(ts) == 6
    assert ts[0] == s and ts[-1] == datetime(2026, 8, 28, 10, 25, tzinfo=UTC)
    # unaligned start snaps down
    assert update_times(s.replace(minute=7), e)[0] == datetime(2026, 8, 28, 10, 5, tzinfo=UTC)


def test_last_bview_before():
    assert last_bview_before(datetime(2026, 8, 27, 20, 0, tzinfo=UTC)) == datetime(2026, 8, 27, 16, 0, tzinfo=UTC)
    assert last_bview_before(datetime(2026, 8, 28, 8, 0, tzinfo=UTC)) == datetime(2026, 8, 28, 8, 0, tzinfo=UTC)
    assert last_bview_before(datetime(2026, 8, 28, 3, 0, tzinfo=UTC)) == datetime(2026, 8, 28, 0, 0, tzinfo=UTC)


def test_plan_counts_default_window():
    s = datetime(2026, 8, 27, 20, 0, tzinfo=UTC)
    e = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
    files = plan(["00", "01"], s, e)
    per_rrc = 64 * 12 + 1  # 64 h of 5-min updates + one bview
    assert len(files) == 2 * per_rrc
    assert sum(f.kind == "bview" for f in files) == 2


def test_crtsh_months_clipped():
    ms = months(date(2024, 11, 15), date(2025, 2, 10))
    assert [month_key(m) for m in ms] == ["2024-11", "2024-12", "2025-01", "2025-02"]
    assert ms[0] == Chunk(date(2024, 11, 15), date(2024, 12, 1))
    assert ms[-1] == Chunk(date(2025, 2, 1), date(2025, 2, 10))
    assert months(date(2024, 12, 1), date(2025, 1, 1)) == [Chunk(date(2024, 12, 1), date(2025, 1, 1))]


def test_crtsh_split_covers_month():
    m = Chunk(date(2026, 3, 1), date(2026, 4, 1))
    parts = _split_to(m, 15)
    assert parts[0].start == m.start and parts[-1].end == m.end
    assert all(p.days <= 16 for p in parts)
    assert all(a.end == b.start for a, b in zip(parts, parts[1:], strict=False))
