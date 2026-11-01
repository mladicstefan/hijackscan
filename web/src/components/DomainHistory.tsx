// One domain in every run, newest first: how its score changed between scans (before / after a fix).
// Shared by the detail panel and "check my domain".

import { useSuspenseQuery } from "@tanstack/react-query";
import { memo } from "react";

import { historyQuery } from "../api/queries";
import type { HistoryRow } from "../api/types";
import { fmtDate } from "../format";
import { openDomain } from "../state/view";
import { SeverityBadge } from "./common";

export default function DomainHistory({ name, currentRun }: { name: string; currentRun?: string }) {
  const { data: rows } = useSuspenseQuery(historyQuery(name));
  if (!rows.length) return <p className="muted">{name} has not been scanned in any run.</p>;
  return (
    <table className="history">
      <thead>
        <tr>
          <th>Run</th>
          <th>Loaded</th>
          <th>Score</th>
          <th>Label</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <Line key={r.run_id} r={r} current={r.run_id === currentRun} />
        ))}
      </tbody>
    </table>
  );
}

const Line = memo(function Line({ r, current }: { r: HistoryRow; current: boolean }) {
  return (
    <tr className={current ? "current" : undefined}>
      <td>
        {current ? (
          <b>{r.run_name ?? r.run_id}</b>
        ) : (
          <button type="button" className="domain-link" onClick={() => openDomain(r.domain, r.run_id)}>
            {r.run_name ?? r.run_id}
          </button>
        )}
      </td>
      <td className="small">{fmtDate(r.loaded_at)}</td>
      <td>
        <SeverityBadge severity={r.severity} score={r.score} />
      </td>
      <td>
        <code>{r.label}</code>
      </td>
    </tr>
  );
});
