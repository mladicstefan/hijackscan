// Who has to act: the hosting networks and DNS operators behind the run's domains, largest first.
// Uses the same run report as the overview (already in the cache: no second request).
// Clicking a provider filters the domains table to it.

import { useSuspenseQuery } from "@tanstack/react-query";
import { memo, useMemo } from "react";

import { runQuery } from "../api/queries";
import type { HostingRow, OperatorRow } from "../api/types";
import { fmtScore, pct } from "../format";
import { setFilters } from "../state/view";
import { SeverityBar } from "./Overview";

const TOP = 12;

// Module-level, so ProviderTable's memo sees the same function on every render.
const pickAsn = (asn: string) => setFilters({ asn, operator: null });
const pickOperator = (operator: string) => setFilters({ operator, asn: null });

function Providers({ runId }: { runId: string }) {
  const { data: r } = useSuspenseQuery(runQuery(runId));
  // Worst exposure first: High or Critical count, then size. Built once per run (the report never changes).
  const hosting = useMemo<ProviderLine[]>(
    () =>
      worstFirst(r.by_hosting_as)
        .slice(0, TOP)
        .map((h) => ({ key: h.asn, name: h.name ?? `AS${h.asn}`, sub: `AS${h.asn}`, row: h, extra: `${h.web_forgeable} with a forgeable web route` })),
    [r.by_hosting_as],
  );
  const operators = useMemo<ProviderLine[]>(
    () =>
      worstFirst(r.by_ns_operator)
        .slice(0, TOP)
        .map((o) => ({ key: o.operator, name: o.operator, sub: null, row: o, extra: `${o.signed} of ${o.domains} DNSSEC-signed` })),
    [r.by_ns_operator],
  );

  return (
    <section className="card providers" aria-labelledby="providers-title">
      <header className="card-head">
        <h2 id="providers-title">Who has to act</h2>
        <span className="muted small">click a row to filter the domains</span>
      </header>
      <div className="two-col">
        <div>
          <h3>Hosting networks (web servers)</h3>
          <ProviderTable rows={hosting} onPick={pickAsn} />
        </div>
        <div>
          <h3>DNS operators (nameservers)</h3>
          <ProviderTable rows={operators} onPick={pickOperator} />
        </div>
      </div>
    </section>
  );
}

function worstFirst<T extends HostingRow | OperatorRow>(rows: T[]): T[] {
  return [...rows].sort((a, b) => b.high_or_critical - a.high_or_critical || b.domains - a.domains);
}

interface ProviderLine {
  key: string;
  name: string;
  sub: string | null;
  row: HostingRow | OperatorRow;
  extra: string;
}

const ProviderTable = memo(function ProviderTable({ rows, onPick }: { rows: ProviderLine[]; onPick: (key: string) => void }) {
  if (!rows.length) return <p className="muted">None in this run.</p>;
  return (
    <table className="provider-table">
      <thead>
        <tr>
          <th>Provider</th>
          <th className="num">Domains</th>
          <th className="num">High / Critical</th>
          <th>Severities</th>
          <th className="num">Mean</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(({ key, name, sub, row, extra }) => (
          <tr key={key}>
            <td>
              <button type="button" className="domain-link" onClick={() => onPick(key)} title={extra}>
                {name}
              </button>
              {sub ? <div className="muted small">{sub}</div> : null}
            </td>
            <td className="num">{row.domains}</td>
            <td className="num">
              <b>{row.high_or_critical}</b> <span className="muted small">{pct(row.high_or_critical, row.domains)}</span>
            </td>
            <td>
              <SeverityBar counts={row.severity} compact />
            </td>
            <td className="num">{fmtScore(row.mean_score)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
});

// memo: props are a run id and URL-derived objects that keep their identity, so re-renders of the page skip this section
export default memo(Providers);
