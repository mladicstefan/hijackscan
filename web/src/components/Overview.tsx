// The run at a glance: severity distribution, defences in place, what each fix would change, and where
// the numbers come from. Aggregate only: no domain names.

import { useSuspenseQuery } from "@tanstack/react-query";
import { memo } from "react";

import { runQuery } from "../api/queries";
import { SEVERITIES, type RunReport, type SeverityCounts } from "../api/types";
import { fmtDate, fmtInt, fmtScore, fmtShare, pct } from "../format";
import { setFilters } from "../state/view";

export const SeverityBar = memo(function SeverityBar({ counts, compact = false }: { counts: SeverityCounts; compact?: boolean }) {
  const total = SEVERITIES.reduce((n, s) => n + counts[s], 0);
  return (
    <div className={compact ? "sevbar compact" : "sevbar"} role="img" aria-label={SEVERITIES.map((s) => `${s} ${counts[s]}`).join(", ")}>
      {SEVERITIES.map((s) =>
        counts[s] ? (
          <span key={s} className={`sev-${s.toLowerCase()}`} style={{ flexGrow: counts[s] }} title={`${s}: ${counts[s]} (${pct(counts[s], total)})`}>
            {compact ? null : counts[s]}
          </span>
        ) : null,
      )}
    </div>
  );
});

function Tile({ value, label, hint }: { value: string; label: string; hint?: string }) {
  return (
    <div className="tile" title={hint}>
      <div className="tile-value">{value}</div>
      <div className="tile-label">{label}</div>
    </div>
  );
}

function Legend({ counts }: { counts: SeverityCounts }) {
  const total = SEVERITIES.reduce((n, s) => n + counts[s], 0);
  return (
    <ul className="legend">
      {SEVERITIES.map((s) => (
        <li key={s}>
          <button type="button" className="linkish" onClick={() => setFilters({ severity: [s] })} title={`Show only ${s}`}>
            <i className={`sw sev-${s.toLowerCase()}`} /> {s} <b>{counts[s]}</b> <span className="muted">{pct(counts[s], total)}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

function Provenance({ r }: { r: RunReport }) {
  const pop = r.scope.population;
  return (
    <dl className="facts">
      <dt>Loaded</dt>
      <dd>{fmtDate(r.loaded_at)}</dd>
      <dt>ROAs of</dt>
      <dd>{r.scope.rpki_date ?? "–"}</dd>
      <dt>Resolver</dt>
      <dd>{r.scope.resolver ?? "–"}</dd>
      <dt>Code version</dt>
      <dd>
        <code>{r.git_commit ?? "unknown"}</code>
      </dd>
      {pop ? (
        <>
          <dt>Sample of</dt>
          <dd>
            {fmtInt(pop.delegations)} delegations in the .{pop.apex} zone (seed {pop.seed}); DS at parent {fmtShare(pop.ds_share)} of
            the zone, {fmtShare(pop.sample_ds_share)} of the sample
          </dd>
        </>
      ) : null}
      {r.missing.length ? (
        <>
          <dt>Not collected</dt>
          <dd>{r.missing.length} domains of the list</dd>
        </>
      ) : null}
    </dl>
  );
}

function Overview({ runId }: { runId: string }) {
  const { data: r } = useSuspenseQuery(runQuery(runId));
  const s = r.summary;
  const n = r.scope.domains;
  const d = r.defences;

  return (
    <section className="card overview" aria-labelledby="overview-title">
      <header className="card-head">
        <h2 id="overview-title">
          {r.name} <span className="muted">· .{r.scope.tld ?? "?"} · {fmtInt(n)} domains</span>
        </h2>
      </header>

      <SeverityBar counts={s.severity} />
      <Legend counts={s.severity} />

      <div className="tiles">
        <Tile value={pct(s.high_or_critical, n)} label="High or Critical" hint={`${s.high_or_critical} of ${n} domains`} />
        <Tile value={fmtScore(s.mean_score)} label="mean score (0–10)" hint={`median ${fmtScore(s.median_score)}, ${s.scored} scored`} />
        <Tile value={pct(d.dnssec_secure, n)} label="DNSSEC signed" hint={`${d.dnssec_secure} secure, ${d.dnssec_bogus} bogus`} />
        <Tile value={pct(d.caa, n)} label="publish CAA" hint={`${d.caa} domains`} />
        <Tile value={pct(d.caa_accounturi, n)} label="CAA with accounturi" hint={`${d.caa_accounturi} domains`} />
      </div>

      <h3>What each fix would change</h3>
      <table className="whatif">
        <thead>
          <tr>
            <th>If</th>
            <th>Severities after</th>
            <th className="num">High or Critical</th>
            <th className="num">Mean</th>
          </tr>
        </thead>
        <tbody>
          <tr className="baseline">
            <td>
              <b>today</b>
            </td>
            <td>
              <SeverityBar counts={s.severity} compact />
            </td>
            <td className="num">{s.high_or_critical}</td>
            <td className="num">{fmtScore(s.mean_score)}</td>
          </tr>
          {r.what_if.map((w) => (
            <tr key={w.scenario}>
              <td>
                <b>{w.scenario}</b>
                <div className="muted small">{w.reads_as}</div>
              </td>
              <td>
                <SeverityBar counts={w.severity} compact />
              </td>
              <td className="num">
                {w.high_or_critical}{" "}
                <Delta now={w.high_or_critical} before={s.high_or_critical} />
              </td>
              <td className="num">{fmtScore(w.mean_score)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <details className="provenance">
        <summary>Where these numbers come from</summary>
        <Provenance r={r} />
      </details>
    </section>
  );
}

function Delta({ now, before }: { now: number; before: number }) {
  const diff = now - before;
  if (!diff) return <span className="muted small">±0</span>;
  return <span className={diff < 0 ? "good small" : "bad small"}>{diff > 0 ? `+${diff}` : diff}</span>;
}

// memo: props are a run id and URL-derived objects that keep their identity, so re-renders of the page skip this section
export default memo(Overview);
