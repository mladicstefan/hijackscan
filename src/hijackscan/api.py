"""Read-only HTTP API over the MongoDB store, for the web page.

hijackscan serve [--host 127.0.0.1] [--port 8000] [--reload]
    http://127.0.0.1:8000/docs    interactive documentation: try every endpoint from the browser

Every endpoint only reads; data gets in through `hijackscan load`. The queries live in store.py,
so this file only maps URLs and parameters to store functions and turns "not found" into 404.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from . import store
from .config import project_root

app = FastAPI(
    title="hijackscan API",
    version="1",
    description="Exposure of domains to certificate theft through BGP hijacks below DNS: runs, domains, filters.",
)


@lru_cache(maxsize=1)
def _connect():
    return store.connect()


def db():
    """One MongoDB connection for the whole server, opened on the first request.
    If MongoDB is down, the request gets a 503 and the next one tries again (a failure is not cached)."""
    try:
        return _connect()
    except SystemExit as e:  # store.connect() exits with a readable message, which must not stop the server
        raise HTTPException(503, str(e)) from None


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


def _run(run_id: str):
    oid = store.run_oid(db(), run_id)
    if oid is None:
        raise HTTPException(404, f"no run with id {run_id}")
    return oid


def filters(
    severity: Annotated[str | None, Query(description="comma list, e.g. `Critical,High`")] = None,
    label: Annotated[str | None, Query(description="comma list, e.g. `open-web,ns-partial`")] = None,
    finding: Annotated[str | None, Query(description="comma list; a domain must have **all** of them")] = None,
    asn: Annotated[str | None, Query(description="hosted by this AS number, e.g. `24940`")] = None,
    operator: Annotated[str | None, Query(description="DNS run by this operator, e.g. `zone.ee`")] = None,
    q: Annotated[str | None, Query(description="the domain name contains this text")] = None,
    min_score: Annotated[float | None, Query(ge=0, le=10, description="score at least this")] = None,
) -> dict:
    """The filters shared by the domains table and its facet counts."""
    return {
        "severity": _csv(severity),
        "label": _csv(label),
        "finding": _csv(finding),
        "asn": asn,
        "operator": operator,
        "q": q,
        "min_score": min_score,
    }


Filters = Annotated[dict, Depends(filters)]


@app.get("/api/runs", summary="Every run, newest first")
def runs():
    return store.list_runs(db())


@app.get("/api/runs/{run_id}", summary="One run's aggregate report (no domain names)")
def run(run_id: str):
    doc = store.get_run(db(), run_id)
    if doc is None:
        raise HTTPException(404, f"no run with id {run_id}")
    return doc


@app.get("/api/runs/{run_id}/domains", summary="Domains of a run: filtered, sorted, one page")
def domains(
    run_id: str,
    f: Filters,
    sort: Literal["score", "domain"] = "score",
    page: Annotated[int, Query(ge=1)] = 1,
    per_page: Annotated[int, Query(ge=1, le=200)] = 50,
):
    query = store.domain_filter(_run(run_id), **f)
    return store.find_domains(db(), query, sort=sort, page=page, per_page=per_page)


@app.get("/api/runs/{run_id}/facets", summary="How many matching domains per severity, label, finding, AS, operator")
def run_facets(run_id: str, f: Filters):
    return store.facets(db(), store.domain_filter(_run(run_id), **f))


@app.get("/api/runs/{run_id}/domains/{domain}", summary="One domain in one run, with every detail")
def domain(run_id: str, domain: str):
    doc = store.get_domain(db(), run_id, domain)
    if doc is None:
        raise HTTPException(404, f"{domain} is not in run {run_id}")
    return doc


@app.get("/api/domains/{domain}", summary="One domain in every run, newest first (check my domain)")
def domain_history(domain: str):
    rows = store.domain_history(db(), domain)
    if not rows:
        raise HTTPException(404, f"{domain} is in no run")
    return rows


# --------------------------------------------------------------------------- the web page

# `npm run build` in web/ writes the page to web/dist: index.html plus assets/ (file names carry a content
# hash). web/dist is not in git, so every machine builds it once. Checked on every request: a build made
# while the server runs shows up on the next refresh, and a missing build explains itself.
WEB_DIST = project_root() / "web" / "dist"

NOT_BUILT = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>hijackscan: page not built</title>
<meta name="color-scheme" content="light dark"></head>
<body style="font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem">
<h1>The web page is not built yet</h1>
<p>The API runs (try <a href="/docs">/docs</a>), but <code>web/dist/</code> does not exist on this machine.
It is generated, not stored in git. Build it once, then refresh this page:</p>
<pre style="background:rgba(127,127,127,.15);padding:.8rem;border-radius:6px">cd web
npm install      # needs Node.js 20.19 or newer
npm run build</pre>
<p>Run them in the same environment as <code>uv</code> (WSL or Windows, not both).</p>
</body></html>"""


@app.get("/", include_in_schema=False)
def page():
    index = WEB_DIST / "index.html"
    if index.is_file():
        # no-cache: after a rebuild the browser fetches the new index.html, which names the new asset files
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
    return HTMLResponse(NOT_BUILT, status_code=503)


# The scripts and styles. check_dir=False: the server also starts before the first build.
app.mount("/assets", StaticFiles(directory=WEB_DIST / "assets", check_dir=False), name="assets")
