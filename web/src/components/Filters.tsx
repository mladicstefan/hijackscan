// The filter panel. Two facet requests run in parallel (useSuspenseQueries, not one after the other):
//   options  every value that exists in the run (unfiltered), so the list does not shrink as you filter
//   counts   how many domains match each value under the current filters
// Both are run-scoped and cached for good; changing filters reuses the options and only fetches counts.

import { useSuspenseQueries } from "@tanstack/react-query";
import { memo, useDeferredValue, useMemo, useState, type FormEvent } from "react";

import { facetsQuery } from "../api/queries";
import { SEVERITIES, type FacetValue, type FilterSet } from "../api/types";
import { NO_FILTERS, clearFilters, setFilters, toggle, type MultiFilter } from "../state/view";

const MIN_SCORES = [
  { value: null, label: "any score" },
  { value: 4, label: "≥ 4.0 (Medium and up)" },
  { value: 7, label: "≥ 7.0 (High and up)" },
  { value: 9, label: "≥ 9.0 (Critical)" },
] as const;

const countsOf = (values: FacetValue[]) => new Map(values.map((v) => [v.value, v.domains]));

function Filters({ runId, filters }: { runId: string; filters: FilterSet }) {
  // While new counts load, keep showing the old ones instead of a placeholder.
  const deferred = useDeferredValue(filters);
  const [{ data: options }, { data: current }] = useSuspenseQueries({
    queries: [facetsQuery(runId, NO_FILTERS), facetsQuery(runId, deferred)],
  });

  const counts = useMemo(
    () => ({
      severity: countsOf(current.severity),
      label: countsOf(current.label),
      finding: countsOf(current.finding),
    }),
    [current],
  );

  const active = filters !== NO_FILTERS && JSON.stringify(filters) !== JSON.stringify(NO_FILTERS);

  return (
    <div className={deferred === filters ? "card filters" : "card filters stale"}>
      <header className="card-head">
        <h2>Filters</h2>
        {active ? (
          <button type="button" className="linkish" onClick={clearFilters}>
            clear all
          </button>
        ) : null}
      </header>

      {/* keyed on q: clearing the filter elsewhere resets the input without an effect */}
      <NameSearch key={filters.q ?? ""} q={filters.q} />

      <fieldset>
        <legend>Severity</legend>
        <div className="chips">
          {SEVERITIES.map((s) => (
            <Chip
              key={s}
              field="severity"
              value={s}
              className={`sev-chip sev-${s.toLowerCase()}`}
              count={counts.severity.get(s) ?? 0}
              on={filters.severity.includes(s)}
            />
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend>Label: what drives the score</legend>
        <div className="chips">
          {options.label.map((o) => (
            <Chip
              key={o.value}
              field="label"
              value={o.value}
              count={counts.label.get(o.value) ?? 0}
              on={filters.label.includes(o.value)}
            />
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend>Findings (all of)</legend>
        <div className="chips">
          {options.finding.map((o) => (
            <Chip
              key={o.value}
              field="finding"
              value={o.value}
              count={counts.finding.get(o.value) ?? 0}
              on={filters.finding.includes(o.value)}
            />
          ))}
        </div>
      </fieldset>

      <label className="field">
        <span>Hosting network (AS)</span>
        <select value={filters.asn ?? ""} onChange={(e) => setFilters({ asn: e.target.value || null })}>
          <option value="">any</option>
          {options.asn.map((o) => (
            <option key={o.value} value={o.value}>
              AS{o.value} {o.name ?? ""} ({o.domains})
            </option>
          ))}
        </select>
      </label>

      <label className="field">
        <span>DNS operator</span>
        <select value={filters.operator ?? ""} onChange={(e) => setFilters({ operator: e.target.value || null })}>
          <option value="">any</option>
          {options.operator.map((o) => (
            <option key={o.value} value={o.value}>
              {o.value} ({o.domains})
            </option>
          ))}
        </select>
      </label>

      <label className="field">
        <span>Score</span>
        <select
          value={filters.minScore ?? ""}
          onChange={(e) => setFilters({ minScore: e.target.value === "" ? null : Number(e.target.value) })}
        >
          {MIN_SCORES.map((m) => (
            <option key={m.label} value={m.value ?? ""}>
              {m.label}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}

/** Plain-value props only (no callbacks), so memo skips every chip whose count and state did not change. */
const Chip = memo(function Chip({
  field,
  value,
  count,
  on,
  className = "",
}: {
  field: MultiFilter;
  value: string;
  count: number;
  on: boolean;
  className?: string;
}) {
  return (
    <button
      type="button"
      className={`chip ${className} ${on ? "on" : ""} ${count === 0 && !on ? "empty" : ""}`}
      aria-pressed={on}
      onClick={() => toggle(field, value)}
    >
      {value} <span className="count">{count}</span>
    </button>
  );
});

/** Local input state; the filter only changes on submit, so typing does not send a request per key. */
function NameSearch({ q }: { q: string | null }) {
  const [text, setText] = useState(q ?? "");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setFilters({ q: text.trim().toLowerCase() || null });
  };
  return (
    <form className="field" onSubmit={submit} role="search">
      <span>Domain name contains</span>
      <div className="inline">
        <input value={text} onChange={(e) => setText(e.target.value)} placeholder="e.g. bank" spellCheck={false} />
        <button type="submit">Filter</button>
      </div>
    </form>
  );
}

// memo: props are a run id and URL-derived objects that keep their identity, so re-renders of the page skip this section
export default memo(Filters);
