// What the page shows (run, filters, page, open domain, lookup) lives in the URL hash, for example
//   #run=6ae6…&severity=Critical,High&asn=24940&page=2&domain=ha.rs
// so every view can be bookmarked, shared or opened directly during a demo.
//
// The hash is read with useSyncExternalStore (React's way to read outside state, no effect needed) and
// written by navigate(), which also gives the browser's back button a history entry per change.

import { useMemo, useSyncExternalStore } from "react";

import { SEVERITIES, type FilterSet, type Severity, type SortKey } from "../api/types";

export const PER_PAGE = 50;

export interface View {
  run: string | null; // null: the newest run
  filters: FilterSet;
  sort: SortKey;
  page: number;
  domain: string | null; // the domain whose details are open
  lookup: string | null; // "check my domain": a name searched across every run
}

export const NO_FILTERS: FilterSet = {
  severity: [],
  label: [],
  finding: [],
  asn: null,
  operator: null,
  q: null,
  minScore: null,
};

// ------------------------------------------------------------------ reading

function subscribe(onChange: () => void): () => void {
  window.addEventListener("hashchange", onChange);
  return () => window.removeEventListener("hashchange", onChange);
}

const readHash = () => window.location.hash;

/** A comma list as a sorted set: `High,Critical` and `Critical,High` are the same filter (and cache key). */
function list(value: string | null): string[] {
  return value ? [...new Set(value.split(",").map((s) => s.trim()).filter(Boolean))].sort() : [];
}

const isSeverity = (s: string): s is Severity => (SEVERITIES as readonly string[]).includes(s);

// Unchanged filters keep the same object across URL changes (opening a domain, turning a page), so
// components memoised on them do not redo work and the table query is not rebuilt.
let lastFilters: { key: string; value: FilterSet } = { key: JSON.stringify(NO_FILTERS), value: NO_FILTERS };

function stable(filters: FilterSet): FilterSet {
  const key = JSON.stringify(filters);
  if (key !== lastFilters.key) lastFilters = { key, value: filters };
  return lastFilters.value;
}

export function parseView(hash: string): View {
  const p = new URLSearchParams(hash.replace(/^#/, ""));
  const min = p.get("min_score");
  const minScore = min === null || min === "" ? null : Number(min);
  const page = Number(p.get("page") ?? "1");
  return {
    run: p.get("run") || null,
    filters: stable({
      severity: list(p.get("severity")).filter(isSeverity),
      label: list(p.get("label")),
      finding: list(p.get("finding")),
      asn: p.get("asn") || null,
      operator: p.get("operator") || null,
      q: p.get("q") || null,
      minScore: minScore !== null && Number.isFinite(minScore) ? minScore : null,
    }),
    sort: p.get("sort") === "domain" ? "domain" : "score",
    page: Number.isInteger(page) && page > 0 ? page : 1,
    domain: p.get("domain") || null,
    lookup: p.get("lookup") || null,
  };
}

/** The current view. The object only changes when the URL hash changes, so it is safe as a memo input. */
export function useView(): View {
  const hash = useSyncExternalStore(subscribe, readHash, () => "");
  return useMemo(() => parseView(hash), [hash]);
}

// ------------------------------------------------------------------ writing

function serialize(v: View): string {
  const p = new URLSearchParams();
  const set = (key: string, value: string | number | null) => {
    if (value !== null && value !== "") p.set(key, String(value));
  };
  set("run", v.run);
  set("severity", v.filters.severity.join(","));
  set("label", v.filters.label.join(","));
  set("finding", v.filters.finding.join(","));
  set("asn", v.filters.asn);
  set("operator", v.filters.operator);
  set("q", v.filters.q);
  set("min_score", v.filters.minScore);
  if (v.sort !== "score") set("sort", v.sort);
  if (v.page > 1) set("page", v.page);
  set("domain", v.domain);
  set("lookup", v.lookup);
  return p.toString().replaceAll("%2C", ","); // readable comma lists in the address bar
}

function go(next: View): void {
  const hash = serialize(next);
  if (hash !== readHash().replace(/^#/, "")) window.location.hash = hash;
}

const current = () => parseView(readHash());

/** Change some filters; the table goes back to page 1, because the old page number means nothing now. */
export function setFilters(patch: Partial<FilterSet>): void {
  const v = current();
  go({ ...v, filters: { ...v.filters, ...patch }, page: 1 });
}

export function clearFilters(): void {
  go({ ...current(), filters: NO_FILTERS, page: 1 });
}

/** Switch run: filters stay (they mean the same in every run), the open domain and the page do not. */
export function setRun(run: string): void {
  go({ ...current(), run, page: 1, domain: null });
}

export function setSort(sort: SortKey): void {
  go({ ...current(), sort, page: 1 });
}

export function setPage(page: number): void {
  go({ ...current(), page });
}

export function openDomain(domain: string | null, run?: string): void {
  const v = current();
  go({ ...v, domain, run: run ?? v.run, lookup: run ? null : v.lookup });
}

export function setLookup(lookup: string | null): void {
  go({ ...current(), lookup });
}

export type MultiFilter = "severity" | "label" | "finding";

/** Toggle one value in a multi-value filter (severity, label, finding). */
export function toggle(key: MultiFilter, value: string): void {
  const values: readonly string[] = current().filters[key];
  const next = values.includes(value) ? values.filter((x) => x !== value) : [...values, value].sort();
  if (key === "severity") setFilters({ severity: next.filter(isSeverity) });
  else if (key === "label") setFilters({ label: next });
  else setFilters({ finding: next });
}
