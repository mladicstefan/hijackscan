"""MongoDB store for the web page. The only module that knows the database layout.

hijackscan load <domains.txt> [--name NAME]    score data/collected (no network) and save it as a new run

Two collections in the `hijackscan` database:
  runs     one document per load: the aggregate report (same content as report.json, no domain names),
           plus when it was loaded, from which list, and which code version computed it
  domains  one document per domain per run: the risk record (same content as a domains.jsonl line),
           plus run_id, tld, finding_ids and facts (hosting AS, DNS operator, DNSSEC, CAA) for filtering

Every load is a new run; nothing is overwritten, so runs can be compared (before / after a fix, .rs / .ee, lab).
Connection: HIJACKSCAN_MONGO_URL (default mongodb://127.0.0.1:27017), database HIJACKSCAN_MONGO_DB (hijackscan).
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from .config import Config, project_root
from .risk import Risk, assess
from .score import Scored, score

MONGO_URL = os.environ.get("HIJACKSCAN_MONGO_URL", "mongodb://127.0.0.1:27017")
DB_NAME = os.environ.get("HIJACKSCAN_MONGO_DB", "hijackscan")


# --------------------------------------------------------------------------- connection


def connect(url: str = MONGO_URL, name: str = DB_NAME):
    """The database handle, after checking that the server answers. Creates missing indexes."""
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError

    client = MongoClient(url, serverSelectionTimeoutMS=3000, tz_aware=True)
    try:
        client.admin.command("ping")
    except PyMongoError as e:
        raise SystemExit(f"MongoDB does not answer at {url}: start it with `docker compose up -d` ({e})") from e
    db = client[name]
    ensure_indexes(db)
    return db


def ensure_indexes(db) -> None:
    """One index per filter the web page offers; creating an index that exists is a no-op."""
    d = db.domains
    d.create_index([("run_id", 1), ("domain", 1)], unique=True)  # a domain appears once per run
    d.create_index([("run_id", 1), ("score", -1)])  # worst first
    d.create_index([("run_id", 1), ("severity", 1)])
    d.create_index([("run_id", 1), ("label", 1)])
    d.create_index([("run_id", 1), ("finding_ids", 1)])
    d.create_index([("run_id", 1), ("facts.hosting_asns.asn", 1)])
    d.create_index([("run_id", 1), ("facts.ns_operators", 1)])
    d.create_index("domain")  # "check my domain" across runs
    db.runs.create_index([("scope.tld", 1), ("loaded_at", -1)])  # newest run per TLD


# --------------------------------------------------------------------------- documents


def facts(s: Scored) -> dict:
    """What the page filters and groups by, taken from the scored record (not in domains.jsonl)."""
    return {
        "dnssec": s.dnssec,
        "has_caa": s.has_caa,
        "pinned": s.pinned,
        "caa_from": s.caa_from,
        "caa_issue": [ca for ca in s.caa.issue if ca],
        "web_forgeable": s.web_forgeable,
        "ns_forgeable": s.ns_forgeable,
        "ns_forgeable_hosts": s.ns_forgeable_hosts,
        "ns_hosts": s.ns_hosts,
        "hosting_asns": [{"asn": asn, "name": name} for asn, name in sorted(s.hosting_asns.items())],
        "ns_operators": s.ns_operators,
    }


def domain_doc(run_id, rec: dict, s: Scored, r: Risk) -> dict:
    return {
        **r.to_json(),
        "run_id": run_id,
        "tld": rec["domain"].rsplit(".", 1)[-1],
        "fetched_at": rec.get("fetched_at"),
        "finding_ids": sorted({f.id for f in r.findings}),
        "facts": facts(s),
    }


def git_commit() -> str | None:
    """Short commit id of the code that computed the numbers; '-dirty' if there were uncommitted changes."""
    root = project_root()

    def git(*args: str) -> str | None:
        try:
            out = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return out.stdout.strip() if out.returncode == 0 else None

    commit = git("rev-parse", "--short", "HEAD")
    if commit and git("status", "--porcelain", "--untracked-files=no"):
        commit += "-dirty"
    return commit


# --------------------------------------------------------------------------- load


def load(cfg: Config, domains: list[str], meta: dict | None, source: str, name: str | None = None) -> dict:
    """Score the collected records of `domains` and save them as a new run. Returns a short summary."""
    from bson import ObjectId

    from .report.zone import build

    records, missing = [], []
    for d in domains:
        p = cfg.collected_dir / f"{d}.json"
        if p.exists():
            records.append(json.loads(p.read_text(encoding="utf-8")))
        else:
            missing.append(d)
    if not records:
        raise SystemExit(f"none of the {len(domains)} domains is collected in {cfg.collected_dir}: run `collect` first")

    # Each record is scored with the routable caps it was collected with (the lab uses longer ones).
    scored = [score(r, caps=tuple(r.get("routable_caps") or cfg.routable_caps)) for r in records]
    risks = [assess(r, s) for r, s in zip(records, scored, strict=True)]
    report = build(records, scored, risks, cfg, meta)

    db = connect()
    run_id = ObjectId()
    # Domains first, the run last: the page only lists runs that exist, so a load that fails half-way
    # never shows up as a run with missing domains.
    db.domains.insert_many([domain_doc(run_id, rec, s, r) for rec, s, r in zip(records, scored, risks, strict=True)])
    db.runs.insert_one(
        {
            "_id": run_id,
            **report,
            "name": name or Path(source).name,
            "source": source,
            "loaded_at": datetime.now(UTC),
            "git_commit": git_commit(),
            "missing": missing,
        }
    )
    return {"run_id": str(run_id), "domains": len(records), "missing": len(missing), "db": f"{MONGO_URL}/{DB_NAME}"}


# --------------------------------------------------------------------------- read (used by the API)

# The domains table shows the summary; `details` (calculation, paths, evidence) is only sent for one domain.
SUMMARY = {"_id": 0, "run_id": 0, "details": 0}
SORTS = {"score": [("score", -1), ("domain", 1)], "domain": [("domain", 1)]}


def _oid(run_id: str):
    """The ObjectId for a run id string, or None if it cannot be one."""
    from bson import ObjectId

    return ObjectId(run_id) if ObjectId.is_valid(run_id) else None


def run_oid(db, run_id: str):
    """The ObjectId of an existing run, or None (bad id or no such run)."""
    oid = _oid(run_id)
    return oid if oid and db.runs.count_documents({"_id": oid}, limit=1) else None


def _run_out(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    return doc


def list_runs(db) -> list[dict]:
    """Every run, newest first, with what a run picker needs."""
    fields = {"name": 1, "source": 1, "loaded_at": 1, "git_commit": 1, "scope": 1, "summary": 1, "missing": 1}
    return [_run_out(r) for r in db.runs.find({}, fields).sort("loaded_at", -1)]


def get_run(db, run_id: str) -> dict | None:
    oid = _oid(run_id)
    doc = db.runs.find_one({"_id": oid}) if oid else None
    return _run_out(doc) if doc else None


def domain_filter(
    oid,
    *,
    severity: Sequence[str] = (),
    label: Sequence[str] = (),
    finding: Sequence[str] = (),
    asn: str | None = None,
    operator: str | None = None,
    q: str | None = None,
    min_score: float | None = None,
) -> dict:
    """The MongoDB query for the domains of one run matching every given filter."""
    import re

    f: dict = {"run_id": oid}
    if severity:
        f["severity"] = {"$in": list(severity)}
    if label:
        f["label"] = {"$in": list(label)}
    if finding:
        f["finding_ids"] = {"$all": list(finding)}  # all of them, not any
    if asn:
        f["facts.hosting_asns.asn"] = asn
    if operator:
        f["facts.ns_operators"] = operator
    if q:
        f["domain"] = {"$regex": re.escape(q.lower())}  # escaped: the text is matched literally
    if min_score is not None:
        f["score"] = {"$gte": min_score}
    return f


def find_domains(db, query: dict, *, sort: str = "score", page: int = 1, per_page: int = 50) -> dict:
    """One page of matching domains (summary only) and how many match in total."""
    total = db.domains.count_documents(query)
    cursor = db.domains.find(query, SUMMARY).sort(SORTS[sort]).skip((page - 1) * per_page).limit(per_page)
    return {"total": total, "page": page, "per_page": per_page, "items": list(cursor)}


def facets(db, query: dict) -> dict:
    """For the domains matching `query`: how many per severity, label, finding, hosting AS and DNS operator."""

    def count(field: str, unwind: str | None = None, name: str | None = None) -> list[dict]:
        stages: list[dict] = [{"$unwind": f"${unwind}"}] if unwind else []
        group: dict = {"_id": f"${field}", "domains": {"$sum": 1}}
        if name:
            group["name"] = {"$first": f"${name}"}
        stages += [{"$group": group}, {"$sort": {"domains": -1, "_id": 1}}]
        return stages

    pipeline = [
        {"$match": query},
        {
            "$facet": {
                "severity": count("severity"),
                "label": count("label"),
                "finding": count("finding_ids", unwind="finding_ids"),
                "asn": count("facts.hosting_asns.asn", unwind="facts.hosting_asns", name="facts.hosting_asns.name"),
                "operator": count("facts.ns_operators", unwind="facts.ns_operators"),
            }
        },
    ]
    out = next(db.domains.aggregate(pipeline))
    return {k: [{"value": x.pop("_id"), **x} for x in v] for k, v in out.items()}


def get_domain(db, run_id: str, domain: str) -> dict | None:
    """One domain's full record in one run, details included."""
    oid = _oid(run_id)
    doc = db.domains.find_one({"run_id": oid, "domain": domain.lower()}, {"_id": 0}) if oid else None
    if doc:
        doc["run_id"] = str(doc["run_id"])
    return doc


def domain_history(db, domain: str) -> list[dict]:
    """One domain in every run that has it, newest run first: for "check my domain" and before/after a fix."""
    rows = list(db.domains.find({"domain": domain.lower()}, {"_id": 0, "details": 0}))
    runs = {r["_id"]: r for r in db.runs.find({"_id": {"$in": [x["run_id"] for x in rows]}}, {"name": 1, "loaded_at": 1})}
    out = []
    for x in rows:
        run = runs.get(x.pop("run_id"))
        if run:  # skip domains of a load that never finished (see load())
            out.append({"run_id": str(run["_id"]), "run_name": run.get("name"), "loaded_at": run["loaded_at"], **x})
    return sorted(out, key=lambda x: x["loaded_at"], reverse=True)
