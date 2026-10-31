from datetime import UTC, date, datetime

from hijackscan.fetch.caida import caida_filename, caida_url
from hijackscan.fetch.ris import RisFile, month_index_url, parse_window
from hijackscan.fetch.rpki import rpki_dir_url
from hijackscan.fetch.tranco import list_page_url

CAIDA = "https://publicdata.caida.org/datasets/as-relationships/serial-2/"


def test_caida_url_uses_first_of_month():
    assert caida_filename(date(2026, 8, 19)) == "20260801.as-rel2.txt.bz2"
    assert caida_url(CAIDA, date(2026, 8, 1)) == CAIDA + "20260801.as-rel2.txt.bz2"


def test_rpki_dir_url():
    assert rpki_dir_url("https://ftp.ripe.net/rpki/", "ripencc", date(2026, 8, 28)) == (
        "https://ftp.ripe.net/rpki/ripencc.tal/2026/08/28/"
    )
    assert rpki_dir_url("https://ftp.ripe.net/ripe/rpki", "arin", date(2026, 1, 5)).startswith(
        "https://ftp.ripe.net/ripe/rpki/arin.tal/2026/01/05/"
    )


def test_ris_file_urls():
    ts = datetime(2026, 8, 28, 10, 5, tzinfo=UTC)
    f = RisFile("00", "updates", ts)
    assert f.name == "updates.20260828.1005.gz"
    assert f.url("https://data.ris.ripe.net/") == "https://data.ris.ripe.net/rrc00/2026.08/updates.20260828.1005.gz"
    b = RisFile("21", "bview", datetime(2026, 8, 27, 16, 0, tzinfo=UTC))
    assert b.url("https://data.ris.ripe.net") == "https://data.ris.ripe.net/rrc21/2026.08/bview.20260827.1600.gz"
    assert month_index_url("https://data.ris.ripe.net", "00", ts) == "https://data.ris.ripe.net/rrc00/2026.08/"


def test_parse_window():
    s, e = parse_window("2026-08-28T10:00Z/2026-08-28T10:30Z")
    assert s == datetime(2026, 8, 28, 10, 0, tzinfo=UTC)
    assert e == datetime(2026, 8, 28, 10, 30, tzinfo=UTC)


def test_tranco_page():
    assert list_page_url("746VX") == "https://tranco-list.eu/list/746VX/"
