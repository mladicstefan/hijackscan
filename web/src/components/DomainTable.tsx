// One page of the run's domains, worst first. The server filters, sorts and pages (50 rows), so the
// page stays fast however many domains a run has.
//
// Changing filters or the page goes through useDeferredValue: React keeps the old rows on screen (dimmed)
// while the new page loads, instead of replacing the table with a placeholder.

import { useSuspenseQuery } from "@tanstack/react-query";
import { memo, useDeferredValue, useMemo } from "react";

import { domainsQuery } from "../api/queries";
import type { DomainQuery, DomainRow, FilterSet, SortKey } from "../api/types";
import { fmtInt, fmtOwner, fmtScore } from "../format";
import { PER_PAGE, openDomain, setPage, setSort } from "../state/view";
import { SeverityBadge } from "./common";

interface Props {
  runId: string;
  filters: FilterSet;
  sort: SortKey;
  page: number;
}

function DomainTable({ runId, filters, sort, page }: Props) {
  const query = useMemo<DomainQuery>(() => ({ ...filters, sort, page, perPage: PER_PAGE }), [filters, sort, page]);
  const deferred = useDeferredValue(query);
  const { data } = useSuspenseQuery(domainsQuery(runId, deferred));
  const stale = deferred !== query;

  const first = data.total ? (data.page - 1) * data.per_page + 1 : 0;
  const last = Math.min(data.page * data.per_page, data.total);
  const pages = Math.max(1, Math.ceil(data.total / data.per_page));

  return (
    <div className={stale ? "card table-card stale" : "card table-card"} aria-busy={stale}>
      <header className="card-head">
        <h2>
          Domains <span className="muted">{fmtInt(data.total)} match</span>
        </h2>
        <label className="inline small">
          sort
          <select value={sort} onChange={(e) => setSort(e.target.value === "domain" ? "domain" : "score")}>
            <option value="score">worst first</option>
            <option value="domain">by name</option>
          </select>
        </label>
      </header>

      {data.items.length ? (
        <div className="table-scroll">
          <table className="domains">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Domain</th>
                <th>Label</th>
                <th>Hosting</th>
                <th>Fix first</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((row) => (
                <Row key={row.domain} row={row} />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="empty">No domain matches these filters.</p>
      )}

      <nav className="pager" aria-label="Pages">
        <button type="button" disabled={data.page <= 1} onClick={() => setPage(data.page - 1)}>
          ← previous
        </button>
        <span>
          {fmtInt(first)}–{fmtInt(last)} of {fmtInt(data.total)} · page {data.page} of {pages}
        </span>
        <button type="button" disabled={data.page >= pages} onClick={() => setPage(data.page + 1)}>
          next →
        </button>
      </nav>
    </div>
  );
}

/** A row only re-renders when its own data changes: `row` is the cached object, stable across renders. */
const Row = memo(function Row({ row }: { row: DomainRow }) {
  const hosting = row.facts.hosting_asns[0];
  const hostingName = hosting ? (hosting.name ?? `AS${hosting.asn}`) : null;
  const fixText = row.fix ? `${fmtOwner(row.fix.owner)} ${row.fix.action} → ${fmtScore(row.fix.score_after)}` : null;
  return (
    <tr>
      <td>
        <SeverityBadge severity={row.severity} score={row.score} />
      </td>
      <td>
        <button type="button" className="domain-link" onClick={() => openDomain(row.domain)} title={row.headline}>
          <DomainLabel domain={row.domain} />
        </button>
      </td>
      <td>
        <code>{row.label}</code>
      </td>
      <td className="small ellipsis" title={hostingName ?? undefined}>
        {hostingName ?? <span className="muted">–</span>}
      </td>
      <td className="small ellipsis" title={fixText ?? undefined}>
        {row.fix ? (
          <>
            <span className="owner">{fmtOwner(row.fix.owner)}</span> {row.fix.action}{" "}
            <span className="muted">→ {fmtScore(row.fix.score_after)}</span>
          </>
        ) : (
          <span className="muted">–</span>
        )}
      </td>
    </tr>
  );
});

/** Breaks only after a label's dot, never mid-label, so long domains wrap cleanly instead of mid-word. */
function DomainLabel({ domain }: { domain: string }) {
  const parts = domain.split(".");
  return (
    <>
      {parts.map((part, i) => (
        <span key={i}>
          {part}
          {i < parts.length - 1 ? (
            <>
              .<wbr />
            </>
          ) : null}
        </span>
      ))}
    </>
  );
}

// memo: props are a run id and URL-derived objects that keep their identity, so re-renders of the page skip this section
export default memo(DomainTable);
